rule TTP_XOR_WriteProcessMemory_a662 {
  strings:
    $key_a662 = { f1 10 [2] c3 32 [2] c5 07 [2] eb 07 [2] d4 1b }

  condition:
    any of them
}