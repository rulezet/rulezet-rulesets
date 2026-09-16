rule TTP_XOR_WriteProcessMemory_b300 {
  strings:
    $key_b300 = { e4 72 [2] d6 50 [2] d0 65 [2] fe 65 [2] c1 79 }

  condition:
    any of them
}