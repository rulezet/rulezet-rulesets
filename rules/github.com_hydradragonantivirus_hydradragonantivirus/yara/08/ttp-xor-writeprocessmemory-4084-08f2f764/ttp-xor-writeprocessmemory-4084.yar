rule TTP_XOR_WriteProcessMemory_4084 {
  strings:
    $key_4084 = { 17 f6 [2] 25 d4 [2] 23 e1 [2] 0d e1 [2] 32 fd }

  condition:
    any of them
}