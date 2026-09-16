rule TTP_XOR_WriteProcessMemory_8dc1 {
  strings:
    $key_8dc1 = { da b3 [2] e8 91 [2] ee a4 [2] c0 a4 [2] ff b8 }

  condition:
    any of them
}