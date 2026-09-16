rule TTP_XOR_WriteProcessMemory_0baa {
  strings:
    $key_0baa = { 5c d8 [2] 6e fa [2] 68 cf [2] 46 cf [2] 79 d3 }

  condition:
    any of them
}