rule TTP_XOR_WriteProcessMemory_b606 {
  strings:
    $key_b606 = { e1 74 [2] d3 56 [2] d5 63 [2] fb 63 [2] c4 7f }

  condition:
    any of them
}