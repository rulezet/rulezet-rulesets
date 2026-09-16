rule TTP_XOR_WriteProcessMemory_4388 {
  strings:
    $key_4388 = { 14 fa [2] 26 d8 [2] 20 ed [2] 0e ed [2] 31 f1 }

  condition:
    any of them
}