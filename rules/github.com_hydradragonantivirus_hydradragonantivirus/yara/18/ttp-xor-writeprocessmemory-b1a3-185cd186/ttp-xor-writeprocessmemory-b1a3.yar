rule TTP_XOR_WriteProcessMemory_b1a3 {
  strings:
    $key_b1a3 = { e6 d1 [2] d4 f3 [2] d2 c6 [2] fc c6 [2] c3 da }

  condition:
    any of them
}