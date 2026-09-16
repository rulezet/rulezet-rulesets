rule TTP_XOR_WriteProcessMemory_db91 {
  strings:
    $key_db91 = { 8c e3 [2] be c1 [2] b8 f4 [2] 96 f4 [2] a9 e8 }

  condition:
    any of them
}