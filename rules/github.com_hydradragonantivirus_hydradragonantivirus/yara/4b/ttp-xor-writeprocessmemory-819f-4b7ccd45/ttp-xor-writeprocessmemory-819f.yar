rule TTP_XOR_WriteProcessMemory_819f {
  strings:
    $key_819f = { d6 ed [2] e4 cf [2] e2 fa [2] cc fa [2] f3 e6 }

  condition:
    any of them
}