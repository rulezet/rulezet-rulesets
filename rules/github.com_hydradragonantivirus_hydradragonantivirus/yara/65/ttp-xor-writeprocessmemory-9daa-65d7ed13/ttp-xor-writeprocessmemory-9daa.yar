rule TTP_XOR_WriteProcessMemory_9daa {
  strings:
    $key_9daa = { ca d8 [2] f8 fa [2] fe cf [2] d0 cf [2] ef d3 }

  condition:
    any of them
}