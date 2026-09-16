rule TTP_XOR_WriteProcessMemory_a3c4 {
  strings:
    $key_a3c4 = { f4 b6 [2] c6 94 [2] c0 a1 [2] ee a1 [2] d1 bd }

  condition:
    any of them
}