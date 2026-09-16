rule TTP_XOR_WriteProcessMemory_a400 {
  strings:
    $key_a400 = { f3 72 [2] c1 50 [2] c7 65 [2] e9 65 [2] d6 79 }

  condition:
    any of them
}