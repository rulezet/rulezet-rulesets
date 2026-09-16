rule TTP_XOR_WriteProcessMemory_b05b {
  strings:
    $key_b05b = { e7 29 [2] d5 0b [2] d3 3e [2] fd 3e [2] c2 22 }

  condition:
    any of them
}