rule TTP_XOR_WriteProcessMemory_b5f6 {
  strings:
    $key_b5f6 = { e2 84 [2] d0 a6 [2] d6 93 [2] f8 93 [2] c7 8f }

  condition:
    any of them
}