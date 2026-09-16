rule TTP_XOR_WriteProcessMemory_b36b {
  strings:
    $key_b36b = { e4 19 [2] d6 3b [2] d0 0e [2] fe 0e [2] c1 12 }

  condition:
    any of them
}