rule TTP_XOR_WriteProcessMemory_db97 {
  strings:
    $key_db97 = { 8c e5 [2] be c7 [2] b8 f2 [2] 96 f2 [2] a9 ee }

  condition:
    any of them
}