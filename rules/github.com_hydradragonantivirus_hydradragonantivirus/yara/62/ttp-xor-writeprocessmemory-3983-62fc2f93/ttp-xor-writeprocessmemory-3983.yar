rule TTP_XOR_WriteProcessMemory_3983 {
  strings:
    $key_3983 = { 6e f1 [2] 5c d3 [2] 5a e6 [2] 74 e6 [2] 4b fa }

  condition:
    any of them
}