rule TTP_XOR_WriteProcessMemory_1983 {
  strings:
    $key_1983 = { 4e f1 [2] 7c d3 [2] 7a e6 [2] 54 e6 [2] 6b fa }

  condition:
    any of them
}