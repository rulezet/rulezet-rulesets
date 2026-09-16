rule TTP_XOR_WriteProcessMemory_969f {
  strings:
    $key_969f = { c1 ed [2] f3 cf [2] f5 fa [2] db fa [2] e4 e6 }

  condition:
    any of them
}