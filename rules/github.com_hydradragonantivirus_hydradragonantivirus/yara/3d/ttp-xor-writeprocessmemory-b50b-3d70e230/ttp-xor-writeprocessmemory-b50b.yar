rule TTP_XOR_WriteProcessMemory_b50b {
  strings:
    $key_b50b = { e2 79 [2] d0 5b [2] d6 6e [2] f8 6e [2] c7 72 }

  condition:
    any of them
}