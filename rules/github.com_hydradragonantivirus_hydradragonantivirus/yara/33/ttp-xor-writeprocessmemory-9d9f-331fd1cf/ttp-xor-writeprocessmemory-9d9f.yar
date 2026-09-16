rule TTP_XOR_WriteProcessMemory_9d9f {
  strings:
    $key_9d9f = { ca ed [2] f8 cf [2] fe fa [2] d0 fa [2] ef e6 }

  condition:
    any of them
}