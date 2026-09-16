rule TTP_XOR_WriteProcessMemory_95d6 {
  strings:
    $key_95d6 = { c2 a4 [2] f0 86 [2] f6 b3 [2] d8 b3 [2] e7 af }

  condition:
    any of them
}