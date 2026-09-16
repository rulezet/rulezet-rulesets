rule TTP_XOR_WriteProcessMemory_74b6 {
  strings:
    $key_74b6 = { 23 c4 [2] 11 e6 [2] 17 d3 [2] 39 d3 [2] 06 cf }

  condition:
    any of them
}