rule TTP_XOR_WriteProcessMemory_60d6 {
  strings:
    $key_60d6 = { 37 a4 [2] 05 86 [2] 03 b3 [2] 2d b3 [2] 12 af }

  condition:
    any of them
}