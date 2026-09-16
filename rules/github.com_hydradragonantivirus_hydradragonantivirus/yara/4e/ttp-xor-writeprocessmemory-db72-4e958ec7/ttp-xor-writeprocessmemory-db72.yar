rule TTP_XOR_WriteProcessMemory_db72 {
  strings:
    $key_db72 = { 8c 00 [2] be 22 [2] b8 17 [2] 96 17 [2] a9 0b }

  condition:
    any of them
}