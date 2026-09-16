rule TTP_XOR_WriteProcessMemory_8988 {
  strings:
    $key_8988 = { de fa [2] ec d8 [2] ea ed [2] c4 ed [2] fb f1 }

  condition:
    any of them
}