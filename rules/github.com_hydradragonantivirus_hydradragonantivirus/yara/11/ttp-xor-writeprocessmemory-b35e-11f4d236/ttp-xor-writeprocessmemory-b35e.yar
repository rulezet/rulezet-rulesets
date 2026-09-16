rule TTP_XOR_WriteProcessMemory_b35e {
  strings:
    $key_b35e = { e4 2c [2] d6 0e [2] d0 3b [2] fe 3b [2] c1 27 }

  condition:
    any of them
}