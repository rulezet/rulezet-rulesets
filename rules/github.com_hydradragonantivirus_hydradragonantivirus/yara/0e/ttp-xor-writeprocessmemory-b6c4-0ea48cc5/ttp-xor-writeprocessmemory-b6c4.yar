rule TTP_XOR_WriteProcessMemory_b6c4 {
  strings:
    $key_b6c4 = { e1 b6 [2] d3 94 [2] d5 a1 [2] fb a1 [2] c4 bd }

  condition:
    any of them
}