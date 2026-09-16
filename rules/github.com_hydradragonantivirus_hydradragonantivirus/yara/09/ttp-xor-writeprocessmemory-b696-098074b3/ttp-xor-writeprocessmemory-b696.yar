rule TTP_XOR_WriteProcessMemory_b696 {
  strings:
    $key_b696 = { e1 e4 [2] d3 c6 [2] d5 f3 [2] fb f3 [2] c4 ef }

  condition:
    any of them
}