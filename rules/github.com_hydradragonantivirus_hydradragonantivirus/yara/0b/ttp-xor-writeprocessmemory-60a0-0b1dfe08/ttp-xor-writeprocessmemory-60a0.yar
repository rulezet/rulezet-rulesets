rule TTP_XOR_WriteProcessMemory_60a0 {
  strings:
    $key_60a0 = { 37 d2 [2] 05 f0 [2] 03 c5 [2] 2d c5 [2] 12 d9 }

  condition:
    any of them
}