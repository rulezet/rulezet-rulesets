rule TTP_XOR_WriteProcessMemory_a04b {
  strings:
    $key_a04b = { f7 39 [2] c5 1b [2] c3 2e [2] ed 2e [2] d2 32 }

  condition:
    any of them
}