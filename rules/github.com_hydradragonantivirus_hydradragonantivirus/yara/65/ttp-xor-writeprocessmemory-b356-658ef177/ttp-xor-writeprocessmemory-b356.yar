rule TTP_XOR_WriteProcessMemory_b356 {
  strings:
    $key_b356 = { e4 24 [2] d6 06 [2] d0 33 [2] fe 33 [2] c1 2f }

  condition:
    any of them
}