rule TTP_XOR_WriteProcessMemory_a6e4 {
  strings:
    $key_a6e4 = { f1 96 [2] c3 b4 [2] c5 81 [2] eb 81 [2] d4 9d }

  condition:
    any of them
}