rule TTP_XOR_WriteProcessMemory_849f {
  strings:
    $key_849f = { d3 ed [2] e1 cf [2] e7 fa [2] c9 fa [2] f6 e6 }

  condition:
    any of them
}