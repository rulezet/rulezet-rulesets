rule TTP_XOR_WriteProcessMemory_a6f2 {
  strings:
    $key_a6f2 = { f1 80 [2] c3 a2 [2] c5 97 [2] eb 97 [2] d4 8b }

  condition:
    any of them
}