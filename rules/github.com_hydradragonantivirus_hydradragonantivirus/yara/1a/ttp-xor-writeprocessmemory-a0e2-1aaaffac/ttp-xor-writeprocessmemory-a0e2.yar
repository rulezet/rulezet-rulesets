rule TTP_XOR_WriteProcessMemory_a0e2 {
  strings:
    $key_a0e2 = { f7 90 [2] c5 b2 [2] c3 87 [2] ed 87 [2] d2 9b }

  condition:
    any of them
}