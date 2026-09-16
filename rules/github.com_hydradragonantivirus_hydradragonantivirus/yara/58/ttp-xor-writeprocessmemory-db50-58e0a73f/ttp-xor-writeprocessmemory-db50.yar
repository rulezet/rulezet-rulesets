rule TTP_XOR_WriteProcessMemory_db50 {
  strings:
    $key_db50 = { 8c 22 [2] be 00 [2] b8 35 [2] 96 35 [2] a9 29 }

  condition:
    any of them
}