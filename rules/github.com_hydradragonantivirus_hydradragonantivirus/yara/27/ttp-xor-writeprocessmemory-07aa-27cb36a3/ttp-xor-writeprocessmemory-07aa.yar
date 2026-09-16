rule TTP_XOR_WriteProcessMemory_07aa {
  strings:
    $key_07aa = { 50 d8 [2] 62 fa [2] 64 cf [2] 4a cf [2] 75 d3 }

  condition:
    any of them
}