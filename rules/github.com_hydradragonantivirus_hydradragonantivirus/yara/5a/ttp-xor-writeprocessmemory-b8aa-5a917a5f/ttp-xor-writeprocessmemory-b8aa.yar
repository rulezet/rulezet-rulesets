rule TTP_XOR_WriteProcessMemory_b8aa {
  strings:
    $key_b8aa = { ef d8 [2] dd fa [2] db cf [2] f5 cf [2] ca d3 }

  condition:
    any of them
}