rule TTP_XOR_WriteProcessMemory_b400 {
  strings:
    $key_b400 = { e3 72 [2] d1 50 [2] d7 65 [2] f9 65 [2] c6 79 }

  condition:
    any of them
}