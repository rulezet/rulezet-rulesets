rule TTP_XOR_WriteProcessMemory_b626 {
  strings:
    $key_b626 = { e1 54 [2] d3 76 [2] d5 43 [2] fb 43 [2] c4 5f }

  condition:
    any of them
}