rule TTP_XOR_WriteProcessMemory_b611 {
  strings:
    $key_b611 = { e1 63 [2] d3 41 [2] d5 74 [2] fb 74 [2] c4 68 }

  condition:
    any of them
}