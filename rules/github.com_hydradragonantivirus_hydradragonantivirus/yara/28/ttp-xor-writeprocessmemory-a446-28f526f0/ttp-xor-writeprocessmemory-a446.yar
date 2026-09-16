rule TTP_XOR_WriteProcessMemory_a446 {
  strings:
    $key_a446 = { f3 34 [2] c1 16 [2] c7 23 [2] e9 23 [2] d6 3f }

  condition:
    any of them
}