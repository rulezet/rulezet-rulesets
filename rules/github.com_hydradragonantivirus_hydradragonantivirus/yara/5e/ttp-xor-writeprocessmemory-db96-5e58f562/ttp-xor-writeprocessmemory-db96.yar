rule TTP_XOR_WriteProcessMemory_db96 {
  strings:
    $key_db96 = { 8c e4 [2] be c6 [2] b8 f3 [2] 96 f3 [2] a9 ef }

  condition:
    any of them
}