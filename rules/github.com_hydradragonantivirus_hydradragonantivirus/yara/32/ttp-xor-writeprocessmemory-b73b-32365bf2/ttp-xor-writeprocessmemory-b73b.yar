rule TTP_XOR_WriteProcessMemory_b73b {
  strings:
    $key_b73b = { e0 49 [2] d2 6b [2] d4 5e [2] fa 5e [2] c5 42 }

  condition:
    any of them
}