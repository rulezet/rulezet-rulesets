rule TTP_XOR_WriteProcessMemory_d740 {
  strings:
    $key_d740 = { 80 32 [2] b2 10 [2] b4 25 [2] 9a 25 [2] a5 39 }

  condition:
    any of them
}