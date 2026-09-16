rule TTP_XOR_WriteProcessMemory_fe83 {
  strings:
    $key_fe83 = { a9 f1 [2] 9b d3 [2] 9d e6 [2] b3 e6 [2] 8c fa }

  condition:
    any of them
}