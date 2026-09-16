rule TTP_XOR_WriteProcessMemory_b0b6 {
  strings:
    $key_b0b6 = { e7 c4 [2] d5 e6 [2] d3 d3 [2] fd d3 [2] c2 cf }

  condition:
    any of them
}