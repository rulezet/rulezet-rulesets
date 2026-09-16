rule TTP_XOR_WriteProcessMemory_6991 {
  strings:
    $key_6991 = { 3e e3 [2] 0c c1 [2] 0a f4 [2] 24 f4 [2] 1b e8 }

  condition:
    any of them
}