rule TTP_XOR_WriteProcessMemory_1e83 {
  strings:
    $key_1e83 = { 49 f1 [2] 7b d3 [2] 7d e6 [2] 53 e6 [2] 6c fa }

  condition:
    any of them
}