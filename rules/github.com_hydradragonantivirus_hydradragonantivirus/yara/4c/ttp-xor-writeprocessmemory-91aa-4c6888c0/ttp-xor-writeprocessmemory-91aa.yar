rule TTP_XOR_WriteProcessMemory_91aa {
  strings:
    $key_91aa = { c6 d8 [2] f4 fa [2] f2 cf [2] dc cf [2] e3 d3 }

  condition:
    any of them
}