rule TTP_XOR_WriteProcessMemory_b615 {
  strings:
    $key_b615 = { e1 67 [2] d3 45 [2] d5 70 [2] fb 70 [2] c4 6c }

  condition:
    any of them
}