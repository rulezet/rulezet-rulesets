rule TTP_XOR_WriteProcessMemory_9c9f {
  strings:
    $key_9c9f = { cb ed [2] f9 cf [2] ff fa [2] d1 fa [2] ee e6 }

  condition:
    any of them
}