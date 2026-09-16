rule TTP_XOR_WriteProcessMemory_a5d2 {
  strings:
    $key_a5d2 = { f2 a0 [2] c0 82 [2] c6 b7 [2] e8 b7 [2] d7 ab }

  condition:
    any of them
}