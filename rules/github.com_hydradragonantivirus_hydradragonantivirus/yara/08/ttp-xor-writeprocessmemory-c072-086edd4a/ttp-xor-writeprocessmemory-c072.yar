rule TTP_XOR_WriteProcessMemory_c072 {
  strings:
    $key_c072 = { 97 00 [2] a5 22 [2] a3 17 [2] 8d 17 [2] b2 0b }

  condition:
    any of them
}