rule TTP_XOR_WriteProcessMemory_a6f0 {
  strings:
    $key_a6f0 = { f1 82 [2] c3 a0 [2] c5 95 [2] eb 95 [2] d4 89 }

  condition:
    any of them
}