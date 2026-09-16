rule TTP_XOR_WriteProcessMemory_94aa {
  strings:
    $key_94aa = { c3 d8 [2] f1 fa [2] f7 cf [2] d9 cf [2] e6 d3 }

  condition:
    any of them
}