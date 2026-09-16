rule TTP_XOR_WriteProcessMemory_b0c3 {
  strings:
    $key_b0c3 = { e7 b1 [2] d5 93 [2] d3 a6 [2] fd a6 [2] c2 ba }

  condition:
    any of them
}