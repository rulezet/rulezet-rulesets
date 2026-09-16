rule TTP_XOR_WriteProcessMemory_a500 {
  strings:
    $key_a500 = { f2 72 [2] c0 50 [2] c6 65 [2] e8 65 [2] d7 79 }

  condition:
    any of them
}