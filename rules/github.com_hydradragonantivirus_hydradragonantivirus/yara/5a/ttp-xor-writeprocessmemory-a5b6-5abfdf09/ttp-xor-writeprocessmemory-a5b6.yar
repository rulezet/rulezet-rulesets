rule TTP_XOR_WriteProcessMemory_a5b6 {
  strings:
    $key_a5b6 = { f2 c4 [2] c0 e6 [2] c6 d3 [2] e8 d3 [2] d7 cf }

  condition:
    any of them
}