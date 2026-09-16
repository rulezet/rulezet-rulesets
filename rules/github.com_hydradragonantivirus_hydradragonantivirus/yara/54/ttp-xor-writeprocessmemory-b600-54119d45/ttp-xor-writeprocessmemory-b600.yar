rule TTP_XOR_WriteProcessMemory_b600 {
  strings:
    $key_b600 = { e1 72 [2] d3 50 [2] d5 65 [2] fb 65 [2] c4 79 }

  condition:
    any of them
}