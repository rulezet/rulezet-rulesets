rule TTP_XOR_WriteProcessMemory_9688 {
  strings:
    $key_9688 = { c1 fa [2] f3 d8 [2] f5 ed [2] db ed [2] e4 f1 }

  condition:
    any of them
}