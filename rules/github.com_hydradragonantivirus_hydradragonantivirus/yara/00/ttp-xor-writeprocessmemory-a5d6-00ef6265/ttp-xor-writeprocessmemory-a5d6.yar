rule TTP_XOR_WriteProcessMemory_a5d6 {
  strings:
    $key_a5d6 = { f2 a4 [2] c0 86 [2] c6 b3 [2] e8 b3 [2] d7 af }

  condition:
    any of them
}