rule TTP_XOR_WriteProcessMemory_929f {
  strings:
    $key_929f = { c5 ed [2] f7 cf [2] f1 fa [2] df fa [2] e0 e6 }

  condition:
    any of them
}