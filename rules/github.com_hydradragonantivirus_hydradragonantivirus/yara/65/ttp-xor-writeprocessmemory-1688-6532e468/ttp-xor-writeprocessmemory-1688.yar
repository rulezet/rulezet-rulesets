rule TTP_XOR_WriteProcessMemory_1688 {
  strings:
    $key_1688 = { 41 fa [2] 73 d8 [2] 75 ed [2] 5b ed [2] 64 f1 }

  condition:
    any of them
}