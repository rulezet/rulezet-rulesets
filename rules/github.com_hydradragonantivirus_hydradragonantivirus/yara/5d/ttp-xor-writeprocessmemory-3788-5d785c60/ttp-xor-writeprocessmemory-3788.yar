rule TTP_XOR_WriteProcessMemory_3788 {
  strings:
    $key_3788 = { 60 fa [2] 52 d8 [2] 54 ed [2] 7a ed [2] 45 f1 }

  condition:
    any of them
}