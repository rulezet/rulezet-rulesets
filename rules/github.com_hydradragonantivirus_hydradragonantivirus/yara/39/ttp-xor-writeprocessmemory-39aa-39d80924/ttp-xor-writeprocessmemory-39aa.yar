rule TTP_XOR_WriteProcessMemory_39aa {
  strings:
    $key_39aa = { 6e d8 [2] 5c fa [2] 5a cf [2] 74 cf [2] 4b d3 }

  condition:
    any of them
}