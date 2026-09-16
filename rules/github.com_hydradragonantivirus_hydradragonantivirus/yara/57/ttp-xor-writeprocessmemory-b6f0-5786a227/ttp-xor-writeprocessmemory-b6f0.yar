rule TTP_XOR_WriteProcessMemory_b6f0 {
  strings:
    $key_b6f0 = { e1 82 [2] d3 a0 [2] d5 95 [2] fb 95 [2] c4 89 }

  condition:
    any of them
}