rule TTP_XOR_WriteProcessMemory_09aa {
  strings:
    $key_09aa = { 5e d8 [2] 6c fa [2] 6a cf [2] 44 cf [2] 7b d3 }

  condition:
    any of them
}