rule TTP_XOR_WriteProcessMemory_b450 {
  strings:
    $key_b450 = { e3 22 [2] d1 00 [2] d7 35 [2] f9 35 [2] c6 29 }

  condition:
    any of them
}