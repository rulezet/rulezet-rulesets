rule TTP_XOR_WriteProcessMemory_a3c0 {
  strings:
    $key_a3c0 = { f4 b2 [2] c6 90 [2] c0 a5 [2] ee a5 [2] d1 b9 }

  condition:
    any of them
}