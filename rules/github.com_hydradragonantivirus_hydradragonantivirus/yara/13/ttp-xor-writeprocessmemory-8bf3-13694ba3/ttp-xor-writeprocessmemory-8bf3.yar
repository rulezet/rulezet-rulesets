rule TTP_XOR_WriteProcessMemory_8bf3 {
  strings:
    $key_8bf3 = { dc 81 [2] ee a3 [2] e8 96 [2] c6 96 [2] f9 8a }

  condition:
    any of them
}