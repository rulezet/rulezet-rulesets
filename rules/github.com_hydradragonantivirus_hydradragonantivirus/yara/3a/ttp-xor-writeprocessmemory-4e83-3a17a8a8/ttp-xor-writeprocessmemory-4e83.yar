rule TTP_XOR_WriteProcessMemory_4e83 {
  strings:
    $key_4e83 = { 19 f1 [2] 2b d3 [2] 2d e6 [2] 03 e6 [2] 3c fa }

  condition:
    any of them
}