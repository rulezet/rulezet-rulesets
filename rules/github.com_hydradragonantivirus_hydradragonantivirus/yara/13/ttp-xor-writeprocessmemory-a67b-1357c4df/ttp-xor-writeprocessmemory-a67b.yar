rule TTP_XOR_WriteProcessMemory_a67b {
  strings:
    $key_a67b = { f1 09 [2] c3 2b [2] c5 1e [2] eb 1e [2] d4 02 }

  condition:
    any of them
}