rule TTP_XOR_WriteProcessMemory_b667 {
  strings:
    $key_b667 = { e1 15 [2] d3 37 [2] d5 02 [2] fb 02 [2] c4 1e }

  condition:
    any of them
}