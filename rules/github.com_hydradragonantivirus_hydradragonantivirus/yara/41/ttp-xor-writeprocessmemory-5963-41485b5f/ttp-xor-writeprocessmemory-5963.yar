rule TTP_XOR_WriteProcessMemory_5963 {
  strings:
    $key_5963 = { 0e 11 [2] 3c 33 [2] 3a 06 [2] 14 06 [2] 2b 1a }

  condition:
    any of them
}