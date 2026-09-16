rule TTP_XOR_WriteProcessMemory_b363 {
  strings:
    $key_b363 = { e4 11 [2] d6 33 [2] d0 06 [2] fe 06 [2] c1 1a }

  condition:
    any of them
}