rule TTP_XOR_WriteProcessMemory_a3c5 {
  strings:
    $key_a3c5 = { f4 b7 [2] c6 95 [2] c0 a0 [2] ee a0 [2] d1 bc }

  condition:
    any of them
}