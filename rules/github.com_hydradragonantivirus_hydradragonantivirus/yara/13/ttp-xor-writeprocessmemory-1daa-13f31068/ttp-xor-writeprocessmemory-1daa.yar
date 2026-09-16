rule TTP_XOR_WriteProcessMemory_1daa {
  strings:
    $key_1daa = { 4a d8 [2] 78 fa [2] 7e cf [2] 50 cf [2] 6f d3 }

  condition:
    any of them
}