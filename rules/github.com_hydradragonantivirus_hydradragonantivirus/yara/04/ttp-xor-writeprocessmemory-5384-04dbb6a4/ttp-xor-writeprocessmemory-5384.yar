rule TTP_XOR_WriteProcessMemory_5384 {
  strings:
    $key_5384 = { 04 f6 [2] 36 d4 [2] 30 e1 [2] 1e e1 [2] 21 fd }

  condition:
    any of them
}