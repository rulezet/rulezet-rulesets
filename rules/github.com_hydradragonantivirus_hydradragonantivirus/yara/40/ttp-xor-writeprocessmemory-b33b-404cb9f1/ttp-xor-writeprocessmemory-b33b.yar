rule TTP_XOR_WriteProcessMemory_b33b {
  strings:
    $key_b33b = { e4 49 [2] d6 6b [2] d0 5e [2] fe 5e [2] c1 42 }

  condition:
    any of them
}