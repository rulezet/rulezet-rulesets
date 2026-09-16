rule TTP_XOR_WriteProcessMemory_a607 {
  strings:
    $key_a607 = { f1 75 [2] c3 57 [2] c5 62 [2] eb 62 [2] d4 7e }

  condition:
    any of them
}