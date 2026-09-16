rule TTP_XOR_WriteProcessMemory_d4d1 {
  strings:
    $key_d4d1 = { 83 a3 [2] b1 81 [2] b7 b4 [2] 99 b4 [2] a6 a8 }

  condition:
    any of them
}