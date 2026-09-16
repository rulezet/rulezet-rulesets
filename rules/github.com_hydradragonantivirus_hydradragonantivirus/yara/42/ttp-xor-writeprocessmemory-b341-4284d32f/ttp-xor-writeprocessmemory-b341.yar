rule TTP_XOR_WriteProcessMemory_b341 {
  strings:
    $key_b341 = { e4 33 [2] d6 11 [2] d0 24 [2] fe 24 [2] c1 38 }

  condition:
    any of them
}