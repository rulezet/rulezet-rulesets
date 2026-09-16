rule TTP_XOR_WriteProcessMemory_a694 {
  strings:
    $key_a694 = { f1 e6 [2] c3 c4 [2] c5 f1 [2] eb f1 [2] d4 ed }

  condition:
    any of them
}