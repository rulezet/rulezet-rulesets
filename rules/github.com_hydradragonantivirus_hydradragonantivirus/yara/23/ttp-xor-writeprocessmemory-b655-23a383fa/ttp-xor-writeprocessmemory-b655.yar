rule TTP_XOR_WriteProcessMemory_b655 {
  strings:
    $key_b655 = { e1 27 [2] d3 05 [2] d5 30 [2] fb 30 [2] c4 2c }

  condition:
    any of them
}