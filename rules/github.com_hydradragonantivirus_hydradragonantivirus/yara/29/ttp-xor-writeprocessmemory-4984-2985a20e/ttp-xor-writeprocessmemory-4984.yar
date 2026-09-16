rule TTP_XOR_WriteProcessMemory_4984 {
  strings:
    $key_4984 = { 1e f6 [2] 2c d4 [2] 2a e1 [2] 04 e1 [2] 3b fd }

  condition:
    any of them
}