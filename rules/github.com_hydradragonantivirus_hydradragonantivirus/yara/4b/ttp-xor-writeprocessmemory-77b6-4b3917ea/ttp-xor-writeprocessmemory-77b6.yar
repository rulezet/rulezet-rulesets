rule TTP_XOR_WriteProcessMemory_77b6 {
  strings:
    $key_77b6 = { 20 c4 [2] 12 e6 [2] 14 d3 [2] 3a d3 [2] 05 cf }

  condition:
    any of them
}