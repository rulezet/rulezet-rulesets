rule TTP_XOR_WriteProcessMemory_50d6 {
  strings:
    $key_50d6 = { 07 a4 [2] 35 86 [2] 33 b3 [2] 1d b3 [2] 22 af }

  condition:
    any of them
}