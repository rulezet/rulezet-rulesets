rule TTP_XOR_WriteProcessMemory_b0c4 {
  strings:
    $key_b0c4 = { e7 b6 [2] d5 94 [2] d3 a1 [2] fd a1 [2] c2 bd }

  condition:
    any of them
}