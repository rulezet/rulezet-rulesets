rule TTP_XOR_WriteProcessMemory_6983 {
  strings:
    $key_6983 = { 3e f1 [2] 0c d3 [2] 0a e6 [2] 24 e6 [2] 1b fa }

  condition:
    any of them
}