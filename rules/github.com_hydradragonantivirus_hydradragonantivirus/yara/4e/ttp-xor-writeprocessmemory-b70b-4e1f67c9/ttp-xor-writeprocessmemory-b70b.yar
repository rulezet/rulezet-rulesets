rule TTP_XOR_WriteProcessMemory_b70b {
  strings:
    $key_b70b = { e0 79 [2] d2 5b [2] d4 6e [2] fa 6e [2] c5 72 }

  condition:
    any of them
}