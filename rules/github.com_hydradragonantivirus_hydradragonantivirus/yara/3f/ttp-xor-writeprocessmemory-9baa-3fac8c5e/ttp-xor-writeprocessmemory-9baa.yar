rule TTP_XOR_WriteProcessMemory_9baa {
  strings:
    $key_9baa = { cc d8 [2] fe fa [2] f8 cf [2] d6 cf [2] e9 d3 }

  condition:
    any of them
}