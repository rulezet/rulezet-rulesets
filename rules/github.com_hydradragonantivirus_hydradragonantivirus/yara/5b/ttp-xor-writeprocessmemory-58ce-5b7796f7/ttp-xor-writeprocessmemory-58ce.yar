rule TTP_XOR_WriteProcessMemory_58ce {
  strings:
    $key_58ce = { 0f bc [2] 3d 9e [2] 3b ab [2] 15 ab [2] 2a b7 }

  condition:
    any of them
}