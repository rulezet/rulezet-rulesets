rule TTP_XOR_WriteProcessMemory_a602 {
  strings:
    $key_a602 = { f1 70 [2] c3 52 [2] c5 67 [2] eb 67 [2] d4 7b }

  condition:
    any of them
}