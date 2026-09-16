rule TTP_XOR_WriteProcessMemory_21b6 {
  strings:
    $key_21b6 = { 76 c4 [2] 44 e6 [2] 42 d3 [2] 6c d3 [2] 53 cf }

  condition:
    any of them
}