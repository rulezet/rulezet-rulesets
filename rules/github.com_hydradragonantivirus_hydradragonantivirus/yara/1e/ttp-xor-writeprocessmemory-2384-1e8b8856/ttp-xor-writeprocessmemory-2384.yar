rule TTP_XOR_WriteProcessMemory_2384 {
  strings:
    $key_2384 = { 74 f6 [2] 46 d4 [2] 40 e1 [2] 6e e1 [2] 51 fd }

  condition:
    any of them
}