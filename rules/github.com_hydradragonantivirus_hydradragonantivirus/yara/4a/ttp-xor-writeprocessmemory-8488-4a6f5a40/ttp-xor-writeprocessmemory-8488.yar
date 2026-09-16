rule TTP_XOR_WriteProcessMemory_8488 {
  strings:
    $key_8488 = { d3 fa [2] e1 d8 [2] e7 ed [2] c9 ed [2] f6 f1 }

  condition:
    any of them
}