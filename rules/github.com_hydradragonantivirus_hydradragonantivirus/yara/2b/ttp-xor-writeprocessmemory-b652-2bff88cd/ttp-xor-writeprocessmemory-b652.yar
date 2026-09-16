rule TTP_XOR_WriteProcessMemory_b652 {
  strings:
    $key_b652 = { e1 20 [2] d3 02 [2] d5 37 [2] fb 37 [2] c4 2b }

  condition:
    any of them
}