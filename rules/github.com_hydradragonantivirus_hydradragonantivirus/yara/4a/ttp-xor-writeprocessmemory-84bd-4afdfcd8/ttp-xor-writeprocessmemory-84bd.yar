rule TTP_XOR_WriteProcessMemory_84bd {
  strings:
    $key_84bd = { d3 cf [2] e1 ed [2] e7 d8 [2] c9 d8 [2] f6 c4 }

  condition:
    any of them
}