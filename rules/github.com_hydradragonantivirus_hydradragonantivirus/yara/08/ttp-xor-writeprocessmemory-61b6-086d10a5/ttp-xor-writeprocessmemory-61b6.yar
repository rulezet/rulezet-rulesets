rule TTP_XOR_WriteProcessMemory_61b6 {
  strings:
    $key_61b6 = { 36 c4 [2] 04 e6 [2] 02 d3 [2] 2c d3 [2] 13 cf }

  condition:
    any of them
}