rule TTP_XOR_WriteProcessMemory_c7d1 {
  strings:
    $key_c7d1 = { 90 a3 [2] a2 81 [2] a4 b4 [2] 8a b4 [2] b5 a8 }

  condition:
    any of them
}