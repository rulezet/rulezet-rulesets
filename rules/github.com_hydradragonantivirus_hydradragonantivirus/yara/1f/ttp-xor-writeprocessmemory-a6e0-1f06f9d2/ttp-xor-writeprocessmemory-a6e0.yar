rule TTP_XOR_WriteProcessMemory_a6e0 {
  strings:
    $key_a6e0 = { f1 92 [2] c3 b0 [2] c5 85 [2] eb 85 [2] d4 99 }

  condition:
    any of them
}