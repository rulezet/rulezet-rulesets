rule TTP_XOR_WriteProcessMemory_81bd {
  strings:
    $key_81bd = { d6 cf [2] e4 ed [2] e2 d8 [2] cc d8 [2] f3 c4 }

  condition:
    any of them
}