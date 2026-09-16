rule TTP_XOR_WriteProcessMemory_5796 {
  strings:
    $key_5796 = { 00 e4 [2] 32 c6 [2] 34 f3 [2] 1a f3 [2] 25 ef }

  condition:
    any of them
}