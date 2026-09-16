rule TTP_XOR_WriteProcessMemory_a6f5 {
  strings:
    $key_a6f5 = { f1 87 [2] c3 a5 [2] c5 90 [2] eb 90 [2] d4 8c }

  condition:
    any of them
}