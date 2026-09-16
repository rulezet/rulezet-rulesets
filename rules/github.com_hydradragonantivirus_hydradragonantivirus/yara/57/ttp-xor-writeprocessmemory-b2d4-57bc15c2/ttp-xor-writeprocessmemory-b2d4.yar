rule TTP_XOR_WriteProcessMemory_b2d4 {
  strings:
    $key_b2d4 = { e5 a6 [2] d7 84 [2] d1 b1 [2] ff b1 [2] c0 ad }

  condition:
    any of them
}