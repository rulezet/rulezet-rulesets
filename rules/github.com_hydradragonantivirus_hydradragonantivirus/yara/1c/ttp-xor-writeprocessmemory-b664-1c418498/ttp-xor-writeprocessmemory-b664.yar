rule TTP_XOR_WriteProcessMemory_b664 {
  strings:
    $key_b664 = { e1 16 [2] d3 34 [2] d5 01 [2] fb 01 [2] c4 1d }

  condition:
    any of them
}