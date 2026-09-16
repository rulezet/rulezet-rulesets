rule TTP_XOR_WriteProcessMemory_7d84 {
  strings:
    $key_7d84 = { 2a f6 [2] 18 d4 [2] 1e e1 [2] 30 e1 [2] 0f fd }

  condition:
    any of them
}