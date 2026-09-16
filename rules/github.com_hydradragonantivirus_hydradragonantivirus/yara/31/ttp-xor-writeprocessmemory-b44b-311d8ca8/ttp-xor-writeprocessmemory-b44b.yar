rule TTP_XOR_WriteProcessMemory_b44b {
  strings:
    $key_b44b = { e3 39 [2] d1 1b [2] d7 2e [2] f9 2e [2] c6 32 }

  condition:
    any of them
}