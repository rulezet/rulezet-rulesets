rule TTP_XOR_WriteProcessMemory_8dc7 {
  strings:
    $key_8dc7 = { da b5 [2] e8 97 [2] ee a2 [2] c0 a2 [2] ff be }

  condition:
    any of them
}