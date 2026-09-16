rule TTP_XOR_WriteProcessMemory_b47b {
  strings:
    $key_b47b = { e3 09 [2] d1 2b [2] d7 1e [2] f9 1e [2] c6 02 }

  condition:
    any of them
}