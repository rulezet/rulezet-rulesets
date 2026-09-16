rule TTP_XOR_WriteProcessMemory_8dc4 {
  strings:
    $key_8dc4 = { da b6 [2] e8 94 [2] ee a1 [2] c0 a1 [2] ff bd }

  condition:
    any of them
}