rule TTP_XOR_WriteProcessMemory_b77b {
  strings:
    $key_b77b = { e0 09 [2] d2 2b [2] d4 1e [2] fa 1e [2] c5 02 }

  condition:
    any of them
}