rule TTP_XOR_WriteProcessMemory_60f9 {
  strings:
    $key_60f9 = { 37 8b [2] 05 a9 [2] 03 9c [2] 2d 9c [2] 12 80 }

  condition:
    any of them
}