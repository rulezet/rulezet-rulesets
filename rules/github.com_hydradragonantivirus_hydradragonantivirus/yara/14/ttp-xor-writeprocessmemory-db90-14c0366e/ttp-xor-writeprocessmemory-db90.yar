rule TTP_XOR_WriteProcessMemory_db90 {
  strings:
    $key_db90 = { 8c e2 [2] be c0 [2] b8 f5 [2] 96 f5 [2] a9 e9 }

  condition:
    any of them
}