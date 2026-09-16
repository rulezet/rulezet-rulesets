rule TTP_XOR_WriteProcessMemory_8a88 {
  strings:
    $key_8a88 = { dd fa [2] ef d8 [2] e9 ed [2] c7 ed [2] f8 f1 }

  condition:
    any of them
}