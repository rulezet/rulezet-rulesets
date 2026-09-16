rule TTP_XOR_WriteProcessMemory_a6e6 {
  strings:
    $key_a6e6 = { f1 94 [2] c3 b6 [2] c5 83 [2] eb 83 [2] d4 9f }

  condition:
    any of them
}