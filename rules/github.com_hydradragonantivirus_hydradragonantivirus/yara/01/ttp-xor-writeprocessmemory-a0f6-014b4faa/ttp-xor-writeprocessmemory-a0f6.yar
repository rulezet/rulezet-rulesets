rule TTP_XOR_WriteProcessMemory_a0f6 {
  strings:
    $key_a0f6 = { f7 84 [2] c5 a6 [2] c3 93 [2] ed 93 [2] d2 8f }

  condition:
    any of them
}