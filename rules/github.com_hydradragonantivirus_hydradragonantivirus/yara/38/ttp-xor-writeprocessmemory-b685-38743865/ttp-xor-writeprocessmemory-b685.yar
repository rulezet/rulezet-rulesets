rule TTP_XOR_WriteProcessMemory_b685 {
  strings:
    $key_b685 = { e1 f7 [2] d3 d5 [2] d5 e0 [2] fb e0 [2] c4 fc }

  condition:
    any of them
}