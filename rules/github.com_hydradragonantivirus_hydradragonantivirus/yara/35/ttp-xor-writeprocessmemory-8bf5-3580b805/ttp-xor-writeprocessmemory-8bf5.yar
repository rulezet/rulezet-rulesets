rule TTP_XOR_WriteProcessMemory_8bf5 {
  strings:
    $key_8bf5 = { dc 87 [2] ee a5 [2] e8 90 [2] c6 90 [2] f9 8c }

  condition:
    any of them
}