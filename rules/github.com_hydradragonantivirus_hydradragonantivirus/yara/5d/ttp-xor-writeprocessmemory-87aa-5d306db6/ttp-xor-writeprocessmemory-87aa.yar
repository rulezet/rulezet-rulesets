rule TTP_XOR_WriteProcessMemory_87aa {
  strings:
    $key_87aa = { d0 d8 [2] e2 fa [2] e4 cf [2] ca cf [2] f5 d3 }

  condition:
    any of them
}