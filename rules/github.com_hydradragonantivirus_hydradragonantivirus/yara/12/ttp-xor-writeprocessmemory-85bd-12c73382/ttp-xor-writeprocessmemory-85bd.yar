rule TTP_XOR_WriteProcessMemory_85bd {
  strings:
    $key_85bd = { d2 cf [2] e0 ed [2] e6 d8 [2] c8 d8 [2] f7 c4 }

  condition:
    any of them
}