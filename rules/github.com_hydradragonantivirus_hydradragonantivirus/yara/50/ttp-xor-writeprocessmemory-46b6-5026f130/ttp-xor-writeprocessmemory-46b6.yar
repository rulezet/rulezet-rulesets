rule TTP_XOR_WriteProcessMemory_46b6 {
  strings:
    $key_46b6 = { 11 c4 [2] 23 e6 [2] 25 d3 [2] 0b d3 [2] 34 cf }

  condition:
    any of them
}