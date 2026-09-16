rule TTP_XOR_WriteProcessMemory_4990 {
  strings:
    $key_4990 = { 1e e2 [2] 2c c0 [2] 2a f5 [2] 04 f5 [2] 3b e9 }

  condition:
    any of them
}