rule TTP_XOR_WriteProcessMemory_1baa {
  strings:
    $key_1baa = { 4c d8 [2] 7e fa [2] 78 cf [2] 56 cf [2] 69 d3 }

  condition:
    any of them
}