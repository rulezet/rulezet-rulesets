rule TTP_XOR_WriteProcessMemory_b377 {
  strings:
    $key_b377 = { e4 05 [2] d6 27 [2] d0 12 [2] fe 12 [2] c1 0e }

  condition:
    any of them
}