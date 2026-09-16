rule TTP_XOR_WriteProcessMemory_a604 {
  strings:
    $key_a604 = { f1 76 [2] c3 54 [2] c5 61 [2] eb 61 [2] d4 7d }

  condition:
    any of them
}