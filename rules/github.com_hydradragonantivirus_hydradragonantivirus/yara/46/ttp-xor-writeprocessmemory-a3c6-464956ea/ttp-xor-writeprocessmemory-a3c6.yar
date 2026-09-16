rule TTP_XOR_WriteProcessMemory_a3c6 {
  strings:
    $key_a3c6 = { f4 b4 [2] c6 96 [2] c0 a3 [2] ee a3 [2] d1 bf }

  condition:
    any of them
}