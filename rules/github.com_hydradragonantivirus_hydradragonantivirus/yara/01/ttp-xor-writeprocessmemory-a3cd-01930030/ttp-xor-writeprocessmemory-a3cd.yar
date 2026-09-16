rule TTP_XOR_WriteProcessMemory_a3cd {
  strings:
    $key_a3cd = { f4 bf [2] c6 9d [2] c0 a8 [2] ee a8 [2] d1 b4 }

  condition:
    any of them
}