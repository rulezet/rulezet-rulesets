rule TTP_XOR_WriteProcessMemory_b00b {
  strings:
    $key_b00b = { e7 79 [2] d5 5b [2] d3 6e [2] fd 6e [2] c2 72 }

  condition:
    any of them
}