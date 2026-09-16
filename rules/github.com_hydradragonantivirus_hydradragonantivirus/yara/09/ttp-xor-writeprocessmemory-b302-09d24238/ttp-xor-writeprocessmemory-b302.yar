rule TTP_XOR_WriteProcessMemory_b302 {
  strings:
    $key_b302 = { e4 70 [2] d6 52 [2] d0 67 [2] fe 67 [2] c1 7b }

  condition:
    any of them
}