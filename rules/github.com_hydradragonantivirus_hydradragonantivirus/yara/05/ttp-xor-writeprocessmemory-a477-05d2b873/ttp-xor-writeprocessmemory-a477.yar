rule TTP_XOR_WriteProcessMemory_a477 {
  strings:
    $key_a477 = { f3 05 [2] c1 27 [2] c7 12 [2] e9 12 [2] d6 0e }

  condition:
    any of them
}