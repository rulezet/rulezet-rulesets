rule TTP_XOR_WriteProcessMemory_4d84 {
  strings:
    $key_4d84 = { 1a f6 [2] 28 d4 [2] 2e e1 [2] 00 e1 [2] 3f fd }

  condition:
    any of them
}