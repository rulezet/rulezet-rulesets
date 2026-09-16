rule TTP_XOR_WriteProcessMemory_a0f3 {
  strings:
    $key_a0f3 = { f7 81 [2] c5 a3 [2] c3 96 [2] ed 96 [2] d2 8a }

  condition:
    any of them
}