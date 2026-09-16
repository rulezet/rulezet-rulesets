rule TTP_XOR_WriteProcessMemory_b1b6 {
  strings:
    $key_b1b6 = { e6 c4 [2] d4 e6 [2] d2 d3 [2] fc d3 [2] c3 cf }

  condition:
    any of them
}