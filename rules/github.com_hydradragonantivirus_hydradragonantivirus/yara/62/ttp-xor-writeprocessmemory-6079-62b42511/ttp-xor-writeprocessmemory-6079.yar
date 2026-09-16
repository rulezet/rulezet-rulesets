rule TTP_XOR_WriteProcessMemory_6079 {
  strings:
    $key_6079 = { 37 0b [2] 05 29 [2] 03 1c [2] 2d 1c [2] 12 00 }

  condition:
    any of them
}