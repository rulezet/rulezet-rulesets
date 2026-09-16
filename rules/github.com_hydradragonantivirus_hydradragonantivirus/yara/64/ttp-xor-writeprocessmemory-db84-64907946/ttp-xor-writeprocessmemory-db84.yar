rule TTP_XOR_WriteProcessMemory_db84 {
  strings:
    $key_db84 = { 8c f6 [2] be d4 [2] b8 e1 [2] 96 e1 [2] a9 fd }

  condition:
    any of them
}