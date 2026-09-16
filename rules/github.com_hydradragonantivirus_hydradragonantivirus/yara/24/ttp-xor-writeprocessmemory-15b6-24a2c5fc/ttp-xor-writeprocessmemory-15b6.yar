rule TTP_XOR_WriteProcessMemory_15b6 {
  strings:
    $key_15b6 = { 42 c4 [2] 70 e6 [2] 76 d3 [2] 58 d3 [2] 67 cf }

  condition:
    any of them
}