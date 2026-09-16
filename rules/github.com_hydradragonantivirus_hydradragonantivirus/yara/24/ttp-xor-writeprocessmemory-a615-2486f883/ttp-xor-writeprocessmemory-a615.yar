rule TTP_XOR_WriteProcessMemory_a615 {
  strings:
    $key_a615 = { f1 67 [2] c3 45 [2] c5 70 [2] eb 70 [2] d4 6c }

  condition:
    any of them
}