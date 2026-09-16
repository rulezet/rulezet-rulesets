rule TTP_XOR_WriteProcessMemory_b332 {
  strings:
    $key_b332 = { e4 40 [2] d6 62 [2] d0 57 [2] fe 57 [2] c1 4b }

  condition:
    any of them
}