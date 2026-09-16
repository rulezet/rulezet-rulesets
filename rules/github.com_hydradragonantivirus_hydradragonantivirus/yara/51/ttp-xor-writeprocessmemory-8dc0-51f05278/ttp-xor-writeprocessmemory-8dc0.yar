rule TTP_XOR_WriteProcessMemory_8dc0 {
  strings:
    $key_8dc0 = { da b2 [2] e8 90 [2] ee a5 [2] c0 a5 [2] ff b9 }

  condition:
    any of them
}