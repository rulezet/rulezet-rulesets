rule TTP_XOR_WriteProcessMemory_a640 {
  strings:
    $key_a640 = { f1 32 [2] c3 10 [2] c5 25 [2] eb 25 [2] d4 39 }

  condition:
    any of them
}