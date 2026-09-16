rule TTP_XOR_WriteProcessMemory_7488 {
  strings:
    $key_7488 = { 23 fa [2] 11 d8 [2] 17 ed [2] 39 ed [2] 06 f1 }

  condition:
    any of them
}