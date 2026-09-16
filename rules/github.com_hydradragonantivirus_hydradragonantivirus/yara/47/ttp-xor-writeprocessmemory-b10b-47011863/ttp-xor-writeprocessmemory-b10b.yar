rule TTP_XOR_WriteProcessMemory_b10b {
  strings:
    $key_b10b = { e6 79 [2] d4 5b [2] d2 6e [2] fc 6e [2] c3 72 }

  condition:
    any of them
}