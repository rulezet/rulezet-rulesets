rule TTP_XOR_WriteProcessMemory_b30b {
  strings:
    $key_b30b = { e4 79 [2] d6 5b [2] d0 6e [2] fe 6e [2] c1 72 }

  condition:
    any of them
}