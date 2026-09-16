rule TTP_XOR_WriteProcessMemory_23b6 {
  strings:
    $key_23b6 = { 74 c4 [2] 46 e6 [2] 40 d3 [2] 6e d3 [2] 51 cf }

  condition:
    any of them
}