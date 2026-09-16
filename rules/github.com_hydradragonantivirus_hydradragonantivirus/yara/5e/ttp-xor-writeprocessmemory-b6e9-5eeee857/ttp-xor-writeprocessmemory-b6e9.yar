rule TTP_XOR_WriteProcessMemory_b6e9 {
  strings:
    $key_b6e9 = { e1 9b [2] d3 b9 [2] d5 8c [2] fb 8c [2] c4 90 }

  condition:
    any of them
}