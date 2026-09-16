rule TTP_XOR_WriteProcessMemory_b176 {
  strings:
    $key_b176 = { e6 04 [2] d4 26 [2] d2 13 [2] fc 13 [2] c3 0f }

  condition:
    any of them
}