rule TTP_XOR_WriteProcessMemory_8dc3 {
  strings:
    $key_8dc3 = { da b1 [2] e8 93 [2] ee a6 [2] c0 a6 [2] ff ba }

  condition:
    any of them
}