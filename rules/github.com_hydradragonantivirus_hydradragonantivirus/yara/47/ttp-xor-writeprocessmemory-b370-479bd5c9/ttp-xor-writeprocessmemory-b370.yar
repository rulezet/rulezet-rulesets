rule TTP_XOR_WriteProcessMemory_b370 {
  strings:
    $key_b370 = { e4 02 [2] d6 20 [2] d0 15 [2] fe 15 [2] c1 09 }

  condition:
    any of them
}