rule TTP_XOR_WriteProcessMemory_b672 {
  strings:
    $key_b672 = { e1 00 [2] d3 22 [2] d5 17 [2] fb 17 [2] c4 0b }

  condition:
    any of them
}