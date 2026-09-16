rule TTP_XOR_WriteProcessMemory_5996 {
  strings:
    $key_5996 = { 0e e4 [2] 3c c6 [2] 3a f3 [2] 14 f3 [2] 2b ef }

  condition:
    any of them
}