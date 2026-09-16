rule TTP_XOR_WriteProcessMemory_47aa {
  strings:
    $key_47aa = { 10 d8 [2] 22 fa [2] 24 cf [2] 0a cf [2] 35 d3 }

  condition:
    any of them
}