rule TTP_XOR_WriteProcessMemory_a2b6 {
  strings:
    $key_a2b6 = { f5 c4 [2] c7 e6 [2] c1 d3 [2] ef d3 [2] d0 cf }

  condition:
    any of them
}