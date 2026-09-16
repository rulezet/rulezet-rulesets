rule TTP_XOR_WriteProcessMemory_86aa {
  strings:
    $key_86aa = { d1 d8 [2] e3 fa [2] e5 cf [2] cb cf [2] f4 d3 }

  condition:
    any of them
}