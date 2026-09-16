rule TTP_XOR_WriteProcessMemory_50d4 {
  strings:
    $key_50d4 = { 07 a6 [2] 35 84 [2] 33 b1 [2] 1d b1 [2] 22 ad }

  condition:
    any of them
}