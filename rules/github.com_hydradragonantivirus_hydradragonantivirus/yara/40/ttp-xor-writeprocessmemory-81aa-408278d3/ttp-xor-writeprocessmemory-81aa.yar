rule TTP_XOR_WriteProcessMemory_81aa {
  strings:
    $key_81aa = { d6 d8 [2] e4 fa [2] e2 cf [2] cc cf [2] f3 d3 }

  condition:
    any of them
}