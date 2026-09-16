rule TTP_XOR_WriteProcessMemory_a5f1 {
  strings:
    $key_a5f1 = { f2 83 [2] c0 a1 [2] c6 94 [2] e8 94 [2] d7 88 }

  condition:
    any of them
}