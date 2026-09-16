rule TTP_XOR_WriteProcessMemory_b65b {
  strings:
    $key_b65b = { e1 29 [2] d3 0b [2] d5 3e [2] fb 3e [2] c4 22 }

  condition:
    any of them
}