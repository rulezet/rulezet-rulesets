rule TTP_XOR_WriteProcessMemory_b732 {
  strings:
    $key_b732 = { e0 40 [2] d2 62 [2] d4 57 [2] fa 57 [2] c5 4b }

  condition:
    any of them
}