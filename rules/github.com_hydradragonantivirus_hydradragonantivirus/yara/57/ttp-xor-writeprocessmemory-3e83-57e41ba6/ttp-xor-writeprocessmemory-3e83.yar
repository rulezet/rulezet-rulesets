rule TTP_XOR_WriteProcessMemory_3e83 {
  strings:
    $key_3e83 = { 69 f1 [2] 5b d3 [2] 5d e6 [2] 73 e6 [2] 4c fa }

  condition:
    any of them
}