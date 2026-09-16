rule TTP_XOR_WriteProcessMemory_60f2 {
  strings:
    $key_60f2 = { 37 80 [2] 05 a2 [2] 03 97 [2] 2d 97 [2] 12 8b }

  condition:
    any of them
}