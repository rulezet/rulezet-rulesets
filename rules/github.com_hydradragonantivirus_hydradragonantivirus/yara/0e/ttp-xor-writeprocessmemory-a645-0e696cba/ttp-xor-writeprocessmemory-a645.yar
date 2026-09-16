rule TTP_XOR_WriteProcessMemory_a645 {
  strings:
    $key_a645 = { f1 37 [2] c3 15 [2] c5 20 [2] eb 20 [2] d4 3c }

  condition:
    any of them
}