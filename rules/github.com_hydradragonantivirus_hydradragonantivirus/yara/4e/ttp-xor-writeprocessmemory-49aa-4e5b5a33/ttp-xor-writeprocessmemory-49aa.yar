rule TTP_XOR_WriteProcessMemory_49aa {
  strings:
    $key_49aa = { 1e d8 [2] 2c fa [2] 2a cf [2] 04 cf [2] 3b d3 }

  condition:
    any of them
}