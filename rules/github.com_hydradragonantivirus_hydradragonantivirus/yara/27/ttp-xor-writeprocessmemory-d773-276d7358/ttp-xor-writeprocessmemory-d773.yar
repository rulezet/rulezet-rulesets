rule TTP_XOR_WriteProcessMemory_d773 {
  strings:
    $key_d773 = { 80 01 [2] b2 23 [2] b4 16 [2] 9a 16 [2] a5 0a }

  condition:
    any of them
}