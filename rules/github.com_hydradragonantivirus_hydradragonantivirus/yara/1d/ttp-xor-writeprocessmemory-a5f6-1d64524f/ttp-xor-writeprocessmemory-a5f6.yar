rule TTP_XOR_WriteProcessMemory_a5f6 {
  strings:
    $key_a5f6 = { f2 84 [2] c0 a6 [2] c6 93 [2] e8 93 [2] d7 8f }

  condition:
    any of them
}