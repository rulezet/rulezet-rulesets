rule TTP_XOR_WriteProcessMemory_869f {
  strings:
    $key_869f = { d1 ed [2] e3 cf [2] e5 fa [2] cb fa [2] f4 e6 }

  condition:
    any of them
}