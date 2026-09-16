rule TTP_XOR_WriteProcessMemory_55aa {
  strings:
    $key_55aa = { 02 d8 [2] 30 fa [2] 36 cf [2] 18 cf [2] 27 d3 }

  condition:
    any of them
}