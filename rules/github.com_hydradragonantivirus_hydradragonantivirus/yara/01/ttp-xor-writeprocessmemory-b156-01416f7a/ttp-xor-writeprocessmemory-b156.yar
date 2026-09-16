rule TTP_XOR_WriteProcessMemory_b156 {
  strings:
    $key_b156 = { e6 24 [2] d4 06 [2] d2 33 [2] fc 33 [2] c3 2f }

  condition:
    any of them
}