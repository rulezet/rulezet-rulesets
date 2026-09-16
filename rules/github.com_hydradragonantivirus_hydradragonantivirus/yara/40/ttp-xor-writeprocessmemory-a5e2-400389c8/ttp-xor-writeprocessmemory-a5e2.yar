rule TTP_XOR_WriteProcessMemory_a5e2 {
  strings:
    $key_a5e2 = { f2 90 [2] c0 b2 [2] c6 87 [2] e8 87 [2] d7 9b }

  condition:
    any of them
}