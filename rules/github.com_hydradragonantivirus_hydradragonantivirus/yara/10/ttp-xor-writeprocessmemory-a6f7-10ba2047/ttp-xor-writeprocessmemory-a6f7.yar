rule TTP_XOR_WriteProcessMemory_a6f7 {
  strings:
    $key_a6f7 = { f1 85 [2] c3 a7 [2] c5 92 [2] eb 92 [2] d4 8e }

  condition:
    any of them
}