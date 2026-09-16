rule TTP_XOR_WriteProcessMemory_b650 {
  strings:
    $key_b650 = { e1 22 [2] d3 00 [2] d5 35 [2] fb 35 [2] c4 29 }

  condition:
    any of them
}