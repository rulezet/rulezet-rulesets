rule TTP_XOR_WriteProcessMemory_b4d6 {
  strings:
    $key_b4d6 = { e3 a4 [2] d1 86 [2] d7 b3 [2] f9 b3 [2] c6 af }

  condition:
    any of them
}