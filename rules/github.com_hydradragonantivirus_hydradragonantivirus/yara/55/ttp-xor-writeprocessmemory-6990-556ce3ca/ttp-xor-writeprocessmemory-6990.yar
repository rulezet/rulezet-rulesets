rule TTP_XOR_WriteProcessMemory_6990 {
  strings:
    $key_6990 = { 3e e2 [2] 0c c0 [2] 0a f5 [2] 24 f5 [2] 1b e9 }

  condition:
    any of them
}