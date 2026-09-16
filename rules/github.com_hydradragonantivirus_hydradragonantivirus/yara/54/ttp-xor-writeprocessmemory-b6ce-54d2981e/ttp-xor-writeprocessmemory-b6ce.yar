rule TTP_XOR_WriteProcessMemory_b6ce {
  strings:
    $key_b6ce = { e1 bc [2] d3 9e [2] d5 ab [2] fb ab [2] c4 b7 }

  condition:
    any of them
}