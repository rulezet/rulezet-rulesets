rule TTP_XOR_WriteProcessMemory_a432 {
  strings:
    $key_a432 = { f3 40 [2] c1 62 [2] c7 57 [2] e9 57 [2] d6 4b }

  condition:
    any of them
}