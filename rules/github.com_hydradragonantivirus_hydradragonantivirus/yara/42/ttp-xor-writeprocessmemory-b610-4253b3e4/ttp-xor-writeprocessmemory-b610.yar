rule TTP_XOR_WriteProcessMemory_b610 {
  strings:
    $key_b610 = { e1 62 [2] d3 40 [2] d5 75 [2] fb 75 [2] c4 69 }

  condition:
    any of them
}