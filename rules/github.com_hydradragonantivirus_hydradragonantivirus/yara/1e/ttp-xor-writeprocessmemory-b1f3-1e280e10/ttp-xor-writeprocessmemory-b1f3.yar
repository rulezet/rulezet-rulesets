rule TTP_XOR_WriteProcessMemory_b1f3 {
  strings:
    $key_b1f3 = { e6 81 [2] d4 a3 [2] d2 96 [2] fc 96 [2] c3 8a }

  condition:
    any of them
}