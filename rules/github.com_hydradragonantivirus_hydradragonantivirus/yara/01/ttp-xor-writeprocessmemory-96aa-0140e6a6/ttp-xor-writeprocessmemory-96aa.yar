rule TTP_XOR_WriteProcessMemory_96aa {
  strings:
    $key_96aa = { c1 d8 [2] f3 fa [2] f5 cf [2] db cf [2] e4 d3 }

  condition:
    any of them
}