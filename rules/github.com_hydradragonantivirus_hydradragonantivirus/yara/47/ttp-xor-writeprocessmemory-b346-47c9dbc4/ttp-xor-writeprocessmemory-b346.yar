rule TTP_XOR_WriteProcessMemory_b346 {
  strings:
    $key_b346 = { e4 34 [2] d6 16 [2] d0 23 [2] fe 23 [2] c1 3f }

  condition:
    any of them
}