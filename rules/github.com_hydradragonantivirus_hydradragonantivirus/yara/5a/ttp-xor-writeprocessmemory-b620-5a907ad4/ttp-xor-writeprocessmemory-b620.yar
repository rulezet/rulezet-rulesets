rule TTP_XOR_WriteProcessMemory_b620 {
  strings:
    $key_b620 = { e1 52 [2] d3 70 [2] d5 45 [2] fb 45 [2] c4 59 }

  condition:
    any of them
}