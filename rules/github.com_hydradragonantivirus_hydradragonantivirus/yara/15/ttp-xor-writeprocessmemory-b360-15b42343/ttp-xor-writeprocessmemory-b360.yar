rule TTP_XOR_WriteProcessMemory_b360 {
  strings:
    $key_b360 = { e4 12 [2] d6 30 [2] d0 05 [2] fe 05 [2] c1 19 }

  condition:
    any of them
}