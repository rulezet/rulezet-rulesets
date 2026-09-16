rule TTP_XOR_WriteProcessMemory_45b6 {
  strings:
    $key_45b6 = { 12 c4 [2] 20 e6 [2] 26 d3 [2] 08 d3 [2] 37 cf }

  condition:
    any of them
}