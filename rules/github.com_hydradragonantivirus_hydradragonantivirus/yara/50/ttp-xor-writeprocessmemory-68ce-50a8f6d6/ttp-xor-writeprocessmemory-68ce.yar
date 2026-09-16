rule TTP_XOR_WriteProcessMemory_68ce {
  strings:
    $key_68ce = { 3f bc [2] 0d 9e [2] 0b ab [2] 25 ab [2] 1a b7 }

  condition:
    any of them
}