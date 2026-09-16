rule TTP_XOR_WriteProcessMemory_db00 {
  strings:
    $key_db00 = { 8c 72 [2] be 50 [2] b8 65 [2] 96 65 [2] a9 79 }

  condition:
    any of them
}