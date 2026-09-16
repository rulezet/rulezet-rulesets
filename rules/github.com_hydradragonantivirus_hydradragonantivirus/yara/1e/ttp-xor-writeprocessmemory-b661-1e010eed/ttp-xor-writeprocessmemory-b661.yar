rule TTP_XOR_WriteProcessMemory_b661 {
  strings:
    $key_b661 = { e1 13 [2] d3 31 [2] d5 04 [2] fb 04 [2] c4 18 }

  condition:
    any of them
}