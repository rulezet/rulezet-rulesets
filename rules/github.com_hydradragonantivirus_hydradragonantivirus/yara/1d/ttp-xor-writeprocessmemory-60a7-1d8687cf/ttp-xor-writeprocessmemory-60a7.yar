rule TTP_XOR_WriteProcessMemory_60a7 {
  strings:
    $key_60a7 = { 37 d5 [2] 05 f7 [2] 03 c2 [2] 2d c2 [2] 12 de }

  condition:
    any of them
}