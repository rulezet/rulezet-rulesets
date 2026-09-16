rule TTP_XOR_WriteProcessMemory_79aa {
  strings:
    $key_79aa = { 2e d8 [2] 1c fa [2] 1a cf [2] 34 cf [2] 0b d3 }

  condition:
    any of them
}