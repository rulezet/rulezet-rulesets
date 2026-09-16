rule TTP_XOR_WriteProcessMemory_a5d4 {
  strings:
    $key_a5d4 = { f2 a6 [2] c0 84 [2] c6 b1 [2] e8 b1 [2] d7 ad }

  condition:
    any of them
}