rule TTP_XOR_WriteProcessMemory_a635 {
  strings:
    $key_a635 = { f1 47 [2] c3 65 [2] c5 50 [2] eb 50 [2] d4 4c }

  condition:
    any of them
}