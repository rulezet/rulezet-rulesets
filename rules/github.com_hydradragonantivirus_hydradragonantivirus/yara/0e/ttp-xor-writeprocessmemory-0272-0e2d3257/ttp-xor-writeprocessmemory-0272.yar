rule TTP_XOR_WriteProcessMemory_0272 {
  strings:
    $key_0272 = { 55 00 [2] 67 22 [2] 61 17 [2] 4f 17 [2] 70 0b }

  condition:
    any of them
}