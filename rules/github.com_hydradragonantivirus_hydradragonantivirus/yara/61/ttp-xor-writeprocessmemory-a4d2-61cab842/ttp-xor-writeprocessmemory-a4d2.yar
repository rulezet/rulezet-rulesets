rule TTP_XOR_WriteProcessMemory_a4d2 {
  strings:
    $key_a4d2 = { f3 a0 [2] c1 82 [2] c7 b7 [2] e9 b7 [2] d6 ab }

  condition:
    any of them
}