rule TTP_XOR_WriteProcessMemory_829f {
  strings:
    $key_829f = { d5 ed [2] e7 cf [2] e1 fa [2] cf fa [2] f0 e6 }

  condition:
    any of them
}