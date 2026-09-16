rule TTP_XOR_WriteProcessMemory_b6e0 {
  strings:
    $key_b6e0 = { e1 92 [2] d3 b0 [2] d5 85 [2] fb 85 [2] c4 99 }

  condition:
    any of them
}