rule TTP_XOR_WriteProcessMemory_db94 {
  strings:
    $key_db94 = { 8c e6 [2] be c4 [2] b8 f1 [2] 96 f1 [2] a9 ed }

  condition:
    any of them
}