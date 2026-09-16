rule TTP_XOR_WriteProcessMemory_b642 {
  strings:
    $key_b642 = { e1 30 [2] d3 12 [2] d5 27 [2] fb 27 [2] c4 3b }

  condition:
    any of them
}