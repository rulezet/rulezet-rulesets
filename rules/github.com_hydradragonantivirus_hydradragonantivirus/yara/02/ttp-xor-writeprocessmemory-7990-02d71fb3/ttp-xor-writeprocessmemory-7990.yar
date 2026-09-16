rule TTP_XOR_WriteProcessMemory_7990 {
  strings:
    $key_7990 = { 2e e2 [2] 1c c0 [2] 1a f5 [2] 34 f5 [2] 0b e9 }

  condition:
    any of them
}