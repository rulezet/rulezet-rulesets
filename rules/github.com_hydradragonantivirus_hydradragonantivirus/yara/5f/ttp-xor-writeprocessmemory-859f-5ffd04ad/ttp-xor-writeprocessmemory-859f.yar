rule TTP_XOR_WriteProcessMemory_859f {
  strings:
    $key_859f = { d2 ed [2] e0 cf [2] e6 fa [2] c8 fa [2] f7 e6 }

  condition:
    any of them
}