rule TTP_XOR_WriteProcessMemory_b1e2 {
  strings:
    $key_b1e2 = { e6 90 [2] d4 b2 [2] d2 87 [2] fc 87 [2] c3 9b }

  condition:
    any of them
}