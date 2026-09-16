rule TTP_XOR_WriteProcessMemory_b6c5 {
  strings:
    $key_b6c5 = { e1 b7 [2] d3 95 [2] d5 a0 [2] fb a0 [2] c4 bc }

  condition:
    any of them
}