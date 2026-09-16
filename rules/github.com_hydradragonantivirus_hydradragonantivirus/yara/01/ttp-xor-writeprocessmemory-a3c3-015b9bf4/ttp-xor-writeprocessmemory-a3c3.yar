rule TTP_XOR_WriteProcessMemory_a3c3 {
  strings:
    $key_a3c3 = { f4 b1 [2] c6 93 [2] c0 a6 [2] ee a6 [2] d1 ba }

  condition:
    any of them
}