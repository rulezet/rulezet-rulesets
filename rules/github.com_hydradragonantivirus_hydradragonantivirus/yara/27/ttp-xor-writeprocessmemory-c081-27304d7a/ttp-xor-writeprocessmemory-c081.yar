rule TTP_XOR_WriteProcessMemory_c081 {
  strings:
    $key_c081 = { 97 f3 [2] a5 d1 [2] a3 e4 [2] 8d e4 [2] b2 f8 }

  condition:
    any of them
}