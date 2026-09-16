rule TTP_XOR_WriteProcessMemory_b367 {
  strings:
    $key_b367 = { e4 15 [2] d6 37 [2] d0 02 [2] fe 02 [2] c1 1e }

  condition:
    any of them
}