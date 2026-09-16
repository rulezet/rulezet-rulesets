rule TTP_XOR_WriteProcessMemory_5084 {
  strings:
    $key_5084 = { 07 f6 [2] 35 d4 [2] 33 e1 [2] 1d e1 [2] 22 fd }

  condition:
    any of them
}