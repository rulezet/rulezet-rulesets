rule TTP_XOR_WriteProcessMemory_5784 {
  strings:
    $key_5784 = { 00 f6 [2] 32 d4 [2] 34 e1 [2] 1a e1 [2] 25 fd }

  condition:
    any of them
}