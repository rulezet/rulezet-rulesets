rule TTP_XOR_WriteProcessMemory_b6d9 {
  strings:
    $key_b6d9 = { e1 ab [2] d3 89 [2] d5 bc [2] fb bc [2] c4 a0 }

  condition:
    any of them
}