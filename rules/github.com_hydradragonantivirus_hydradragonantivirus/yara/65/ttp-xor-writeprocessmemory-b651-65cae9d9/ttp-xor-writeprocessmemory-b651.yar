rule TTP_XOR_WriteProcessMemory_b651 {
  strings:
    $key_b651 = { e1 23 [2] d3 01 [2] d5 34 [2] fb 34 [2] c4 28 }

  condition:
    any of them
}