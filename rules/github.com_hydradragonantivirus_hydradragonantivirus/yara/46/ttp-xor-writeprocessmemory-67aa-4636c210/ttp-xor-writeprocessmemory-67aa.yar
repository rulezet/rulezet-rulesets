rule TTP_XOR_WriteProcessMemory_67aa {
  strings:
    $key_67aa = { 30 d8 [2] 02 fa [2] 04 cf [2] 2a cf [2] 15 d3 }

  condition:
    any of them
}