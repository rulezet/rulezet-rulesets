rule TTP_XOR_WriteProcessMemory_48ce {
  strings:
    $key_48ce = { 1f bc [2] 2d 9e [2] 2b ab [2] 05 ab [2] 3a b7 }

  condition:
    any of them
}