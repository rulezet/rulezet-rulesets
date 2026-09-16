rule TTP_XOR_WriteProcessMemory_d6d1 {
  strings:
    $key_d6d1 = { 81 a3 [2] b3 81 [2] b5 b4 [2] 9b b4 [2] a4 a8 }

  condition:
    any of them
}