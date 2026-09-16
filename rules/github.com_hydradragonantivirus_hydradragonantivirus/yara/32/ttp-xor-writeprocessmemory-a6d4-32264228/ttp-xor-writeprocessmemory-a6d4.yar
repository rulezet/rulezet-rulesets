rule TTP_XOR_WriteProcessMemory_a6d4 {
  strings:
    $key_a6d4 = { f1 a6 [2] c3 84 [2] c5 b1 [2] eb b1 [2] d4 ad }

  condition:
    any of them
}