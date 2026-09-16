rule TTP_XOR_WriteProcessMemory_8288 {
  strings:
    $key_8288 = { d5 fa [2] e7 d8 [2] e1 ed [2] cf ed [2] f0 f1 }

  condition:
    any of them
}