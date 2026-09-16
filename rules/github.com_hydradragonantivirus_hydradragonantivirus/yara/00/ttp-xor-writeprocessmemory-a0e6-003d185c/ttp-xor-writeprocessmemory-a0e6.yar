rule TTP_XOR_WriteProcessMemory_a0e6 {
  strings:
    $key_a0e6 = { f7 94 [2] c5 b6 [2] c3 83 [2] ed 83 [2] d2 9f }

  condition:
    any of them
}