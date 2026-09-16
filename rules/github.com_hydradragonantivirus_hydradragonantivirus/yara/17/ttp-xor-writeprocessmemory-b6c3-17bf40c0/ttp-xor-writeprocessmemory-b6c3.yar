rule TTP_XOR_WriteProcessMemory_b6c3 {
  strings:
    $key_b6c3 = { e1 b1 [2] d3 93 [2] d5 a6 [2] fb a6 [2] c4 ba }

  condition:
    any of them
}