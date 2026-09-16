rule TTP_XOR_WriteProcessMemory_8588 {
  strings:
    $key_8588 = { d2 fa [2] e0 d8 [2] e6 ed [2] c8 ed [2] f7 f1 }

  condition:
    any of them
}