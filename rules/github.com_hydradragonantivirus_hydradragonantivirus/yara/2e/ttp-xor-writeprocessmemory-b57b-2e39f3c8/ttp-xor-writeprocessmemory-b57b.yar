rule TTP_XOR_WriteProcessMemory_b57b {
  strings:
    $key_b57b = { e2 09 [2] d0 2b [2] d6 1e [2] f8 1e [2] c7 02 }

  condition:
    any of them
}