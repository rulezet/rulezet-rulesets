rule TTP_XOR_WriteProcessMemory_b373 {
  strings:
    $key_b373 = { e4 01 [2] d6 23 [2] d0 16 [2] fe 16 [2] c1 0a }

  condition:
    any of them
}