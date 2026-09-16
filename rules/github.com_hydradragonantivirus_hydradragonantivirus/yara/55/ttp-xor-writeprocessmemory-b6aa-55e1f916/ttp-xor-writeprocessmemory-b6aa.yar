rule TTP_XOR_WriteProcessMemory_b6aa {
  strings:
    $key_b6aa = { e1 d8 [2] d3 fa [2] d5 cf [2] fb cf [2] c4 d3 }

  condition:
    any of them
}