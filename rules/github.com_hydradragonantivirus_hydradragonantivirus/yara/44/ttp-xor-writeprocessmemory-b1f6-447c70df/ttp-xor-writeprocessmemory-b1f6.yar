rule TTP_XOR_WriteProcessMemory_b1f6 {
  strings:
    $key_b1f6 = { e6 84 [2] d4 a6 [2] d2 93 [2] fc 93 [2] c3 8f }

  condition:
    any of them
}