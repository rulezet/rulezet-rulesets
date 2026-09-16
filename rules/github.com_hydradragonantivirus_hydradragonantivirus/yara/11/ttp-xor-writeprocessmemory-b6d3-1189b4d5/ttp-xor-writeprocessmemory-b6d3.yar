rule TTP_XOR_WriteProcessMemory_b6d3 {
  strings:
    $key_b6d3 = { e1 a1 [2] d3 83 [2] d5 b6 [2] fb b6 [2] c4 aa }

  condition:
    any of them
}