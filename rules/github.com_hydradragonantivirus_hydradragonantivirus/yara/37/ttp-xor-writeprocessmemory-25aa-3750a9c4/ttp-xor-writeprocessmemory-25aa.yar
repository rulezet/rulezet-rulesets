rule TTP_XOR_WriteProcessMemory_25aa {
  strings:
    $key_25aa = { 72 d8 [2] 40 fa [2] 46 cf [2] 68 cf [2] 57 d3 }

  condition:
    any of them
}