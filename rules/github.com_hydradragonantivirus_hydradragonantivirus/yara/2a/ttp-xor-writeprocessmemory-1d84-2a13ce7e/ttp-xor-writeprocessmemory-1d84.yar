rule TTP_XOR_WriteProcessMemory_1d84 {
  strings:
    $key_1d84 = { 4a f6 [2] 78 d4 [2] 7e e1 [2] 50 e1 [2] 6f fd }

  condition:
    any of them
}