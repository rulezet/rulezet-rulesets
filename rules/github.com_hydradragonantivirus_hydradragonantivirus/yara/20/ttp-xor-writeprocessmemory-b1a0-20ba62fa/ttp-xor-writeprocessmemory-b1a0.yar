rule TTP_XOR_WriteProcessMemory_b1a0 {
  strings:
    $key_b1a0 = { e6 d2 [2] d4 f0 [2] d2 c5 [2] fc c5 [2] c3 d9 }

  condition:
    any of them
}