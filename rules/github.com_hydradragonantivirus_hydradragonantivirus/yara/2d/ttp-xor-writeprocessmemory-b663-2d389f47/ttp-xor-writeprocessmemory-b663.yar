rule TTP_XOR_WriteProcessMemory_b663 {
  strings:
    $key_b663 = { e1 11 [2] d3 33 [2] d5 06 [2] fb 06 [2] c4 1a }

  condition:
    any of them
}