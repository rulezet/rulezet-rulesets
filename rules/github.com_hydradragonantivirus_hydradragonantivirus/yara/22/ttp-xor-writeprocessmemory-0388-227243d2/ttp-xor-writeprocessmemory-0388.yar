rule TTP_XOR_WriteProcessMemory_0388 {
  strings:
    $key_0388 = { 54 fa [2] 66 d8 [2] 60 ed [2] 4e ed [2] 71 f1 }

  condition:
    any of them
}