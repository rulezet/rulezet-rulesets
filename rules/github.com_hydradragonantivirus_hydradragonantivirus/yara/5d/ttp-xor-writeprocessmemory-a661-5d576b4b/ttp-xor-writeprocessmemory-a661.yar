rule TTP_XOR_WriteProcessMemory_a661 {
  strings:
    $key_a661 = { f1 13 [2] c3 31 [2] c5 04 [2] eb 04 [2] d4 18 }

  condition:
    any of them
}