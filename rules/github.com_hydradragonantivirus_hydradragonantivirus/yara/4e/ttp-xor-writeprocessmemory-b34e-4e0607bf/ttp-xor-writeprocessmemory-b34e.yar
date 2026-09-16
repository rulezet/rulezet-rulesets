rule TTP_XOR_WriteProcessMemory_b34e {
  strings:
    $key_b34e = { e4 3c [2] d6 1e [2] d0 2b [2] fe 2b [2] c1 37 }

  condition:
    any of them
}