rule TTP_XOR_WriteProcessMemory_b61b {
  strings:
    $key_b61b = { e1 69 [2] d3 4b [2] d5 7e [2] fb 7e [2] c4 62 }

  condition:
    any of them
}