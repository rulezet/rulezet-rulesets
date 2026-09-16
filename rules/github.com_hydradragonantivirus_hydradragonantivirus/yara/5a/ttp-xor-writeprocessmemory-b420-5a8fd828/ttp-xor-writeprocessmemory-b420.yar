rule TTP_XOR_WriteProcessMemory_b420 {
  strings:
    $key_b420 = { e3 52 [2] d1 70 [2] d7 45 [2] f9 45 [2] c6 59 }

  condition:
    any of them
}