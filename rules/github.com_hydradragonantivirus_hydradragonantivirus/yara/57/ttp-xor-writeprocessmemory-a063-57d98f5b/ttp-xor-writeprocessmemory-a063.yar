rule TTP_XOR_WriteProcessMemory_a063 {
  strings:
    $key_a063 = { f7 11 [2] c5 33 [2] c3 06 [2] ed 06 [2] d2 1a }

  condition:
    any of them
}