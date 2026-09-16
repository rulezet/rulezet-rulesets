rule TTP_XOR_WriteProcessMemory_b342 {
  strings:
    $key_b342 = { e4 30 [2] d6 12 [2] d0 27 [2] fe 27 [2] c1 3b }

  condition:
    any of them
}