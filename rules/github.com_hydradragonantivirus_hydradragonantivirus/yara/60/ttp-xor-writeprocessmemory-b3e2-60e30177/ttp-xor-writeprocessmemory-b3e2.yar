rule TTP_XOR_WriteProcessMemory_b3e2 {
  strings:
    $key_b3e2 = { e4 90 [2] d6 b2 [2] d0 87 [2] fe 87 [2] c1 9b }

  condition:
    any of them
}