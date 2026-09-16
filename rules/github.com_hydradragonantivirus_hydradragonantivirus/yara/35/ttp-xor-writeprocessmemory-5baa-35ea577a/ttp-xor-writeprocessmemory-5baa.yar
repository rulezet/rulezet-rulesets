rule TTP_XOR_WriteProcessMemory_5baa {
  strings:
    $key_5baa = { 0c d8 [2] 3e fa [2] 38 cf [2] 16 cf [2] 29 d3 }

  condition:
    any of them
}