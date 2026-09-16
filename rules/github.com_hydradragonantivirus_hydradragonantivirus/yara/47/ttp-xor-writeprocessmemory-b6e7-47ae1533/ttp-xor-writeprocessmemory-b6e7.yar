rule TTP_XOR_WriteProcessMemory_b6e7 {
  strings:
    $key_b6e7 = { e1 95 [2] d3 b7 [2] d5 82 [2] fb 82 [2] c4 9e }

  condition:
    any of them
}