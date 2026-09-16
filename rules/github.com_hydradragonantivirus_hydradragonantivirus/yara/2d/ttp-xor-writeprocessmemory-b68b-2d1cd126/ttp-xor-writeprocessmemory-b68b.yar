rule TTP_XOR_WriteProcessMemory_b68b {
  strings:
    $key_b68b = { e1 f9 [2] d3 db [2] d5 ee [2] fb ee [2] c4 f2 }

  condition:
    any of them
}