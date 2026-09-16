rule TTP_XOR_WriteProcessMemory_60a6 {
  strings:
    $key_60a6 = { 37 d4 [2] 05 f6 [2] 03 c3 [2] 2d c3 [2] 12 df }

  condition:
    any of them
}