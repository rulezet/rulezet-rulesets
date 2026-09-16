rule TTP_XOR_WriteProcessMemory_a622 {
  strings:
    $key_a622 = { f1 50 [2] c3 72 [2] c5 47 [2] eb 47 [2] d4 5b }

  condition:
    any of them
}