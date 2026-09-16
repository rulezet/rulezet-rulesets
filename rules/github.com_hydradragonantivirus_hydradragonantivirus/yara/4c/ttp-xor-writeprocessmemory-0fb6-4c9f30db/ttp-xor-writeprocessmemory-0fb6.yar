rule TTP_XOR_WriteProcessMemory_0fb6 {
  strings:
    $key_0fb6 = { 58 c4 [2] 6a e6 [2] 6c d3 [2] 42 d3 [2] 7d cf }

  condition:
    any of them
}