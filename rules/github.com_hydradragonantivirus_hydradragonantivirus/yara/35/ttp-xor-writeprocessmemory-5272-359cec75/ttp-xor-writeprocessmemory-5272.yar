rule TTP_XOR_WriteProcessMemory_5272 {
  strings:
    $key_5272 = { 05 00 [2] 37 22 [2] 31 17 [2] 1f 17 [2] 20 0b }

  condition:
    any of them
}