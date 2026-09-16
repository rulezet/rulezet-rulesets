rule TTP_XOR_WriteProcessMemory_63d7 {
  strings:
    $key_63d7 = { 34 a5 [2] 06 87 [2] 00 b2 [2] 2e b2 [2] 11 ae }

  condition:
    any of them
}