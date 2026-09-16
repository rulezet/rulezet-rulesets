rule TTP_XOR_WriteProcessMemory_b1e0 {
  strings:
    $key_b1e0 = { e6 92 [2] d4 b0 [2] d2 85 [2] fc 85 [2] c3 99 }

  condition:
    any of them
}