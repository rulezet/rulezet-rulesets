rule TTP_XOR_WriteProcessMemory_6388 {
  strings:
    $key_6388 = { 34 fa [2] 06 d8 [2] 00 ed [2] 2e ed [2] 11 f1 }

  condition:
    any of them
}