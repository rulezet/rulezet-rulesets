rule TTP_XOR_WriteProcessMemory_b146 {
  strings:
    $key_b146 = { e6 34 [2] d4 16 [2] d2 23 [2] fc 23 [2] c3 3f }

  condition:
    any of them
}