rule TTP_XOR_WriteProcessMemory_a576 {
  strings:
    $key_a576 = { f2 04 [2] c0 26 [2] c6 13 [2] e8 13 [2] d7 0f }

  condition:
    any of them
}