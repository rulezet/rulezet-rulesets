rule TTP_XOR_WriteProcessMemory_c4d1 {
  strings:
    $key_c4d1 = { 93 a3 [2] a1 81 [2] a7 b4 [2] 89 b4 [2] b6 a8 }

  condition:
    any of them
}