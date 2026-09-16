rule TTP_XOR_WriteProcessMemory_b03b {
  strings:
    $key_b03b = { e7 49 [2] d5 6b [2] d3 5e [2] fd 5e [2] c2 42 }

  condition:
    any of them
}