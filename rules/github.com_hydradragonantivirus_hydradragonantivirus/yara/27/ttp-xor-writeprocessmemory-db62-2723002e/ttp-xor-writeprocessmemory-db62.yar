rule TTP_XOR_WriteProcessMemory_db62 {
  strings:
    $key_db62 = { 8c 10 [2] be 32 [2] b8 07 [2] 96 07 [2] a9 1b }

  condition:
    any of them
}