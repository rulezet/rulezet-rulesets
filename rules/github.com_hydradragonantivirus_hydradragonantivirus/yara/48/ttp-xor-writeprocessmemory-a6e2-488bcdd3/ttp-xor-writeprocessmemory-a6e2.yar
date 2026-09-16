rule TTP_XOR_WriteProcessMemory_a6e2 {
  strings:
    $key_a6e2 = { f1 90 [2] c3 b2 [2] c5 87 [2] eb 87 [2] d4 9b }

  condition:
    any of them
}