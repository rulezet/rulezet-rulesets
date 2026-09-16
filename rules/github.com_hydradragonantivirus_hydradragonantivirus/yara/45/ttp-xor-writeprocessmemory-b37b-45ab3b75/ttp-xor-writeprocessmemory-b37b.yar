rule TTP_XOR_WriteProcessMemory_b37b {
  strings:
    $key_b37b = { e4 09 [2] d6 2b [2] d0 1e [2] fe 1e [2] c1 02 }

  condition:
    any of them
}