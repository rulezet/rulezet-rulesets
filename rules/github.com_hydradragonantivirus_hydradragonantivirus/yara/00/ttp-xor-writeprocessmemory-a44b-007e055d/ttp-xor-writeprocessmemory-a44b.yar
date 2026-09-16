rule TTP_XOR_WriteProcessMemory_a44b {
  strings:
    $key_a44b = { f3 39 [2] c1 1b [2] c7 2e [2] e9 2e [2] d6 32 }

  condition:
    any of them
}