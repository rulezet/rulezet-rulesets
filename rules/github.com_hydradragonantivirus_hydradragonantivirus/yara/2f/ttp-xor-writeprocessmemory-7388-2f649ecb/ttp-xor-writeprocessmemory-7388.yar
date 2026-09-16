rule TTP_XOR_WriteProcessMemory_7388 {
  strings:
    $key_7388 = { 24 fa [2] 16 d8 [2] 10 ed [2] 3e ed [2] 01 f1 }

  condition:
    any of them
}