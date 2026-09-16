rule TTP_XOR_WriteProcessMemory_95aa {
  strings:
    $key_95aa = { c2 d8 [2] f0 fa [2] f6 cf [2] d8 cf [2] e7 d3 }

  condition:
    any of them
}