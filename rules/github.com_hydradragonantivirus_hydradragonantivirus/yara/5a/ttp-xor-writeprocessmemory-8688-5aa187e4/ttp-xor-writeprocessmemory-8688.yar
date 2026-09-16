rule TTP_XOR_WriteProcessMemory_8688 {
  strings:
    $key_8688 = { d1 fa [2] e3 d8 [2] e5 ed [2] cb ed [2] f4 f1 }

  condition:
    any of them
}