rule TTP_XOR_WriteProcessMemory_8bf4 {
  strings:
    $key_8bf4 = { dc 86 [2] ee a4 [2] e8 91 [2] c6 91 [2] f9 8d }

  condition:
    any of them
}