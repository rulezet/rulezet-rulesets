rule TTP_XOR_WriteProcessMemory_a562 {
  strings:
    $key_a562 = { f2 10 [2] c0 32 [2] c6 07 [2] e8 07 [2] d7 1b }

  condition:
    any of them
}