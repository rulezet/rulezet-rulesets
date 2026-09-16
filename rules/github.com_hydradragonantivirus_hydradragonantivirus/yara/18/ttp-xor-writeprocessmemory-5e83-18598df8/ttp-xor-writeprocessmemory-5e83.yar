rule TTP_XOR_WriteProcessMemory_5e83 {
  strings:
    $key_5e83 = { 09 f1 [2] 3b d3 [2] 3d e6 [2] 13 e6 [2] 2c fa }

  condition:
    any of them
}