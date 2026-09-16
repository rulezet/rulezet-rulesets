rule TTP_XOR_WriteProcessMemory_45aa {
  strings:
    $key_45aa = { 12 d8 [2] 20 fa [2] 26 cf [2] 08 cf [2] 37 d3 }

  condition:
    any of them
}