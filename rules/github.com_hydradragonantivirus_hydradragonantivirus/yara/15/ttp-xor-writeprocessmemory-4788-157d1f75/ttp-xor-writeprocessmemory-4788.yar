rule TTP_XOR_WriteProcessMemory_4788 {
  strings:
    $key_4788 = { 10 fa [2] 22 d8 [2] 24 ed [2] 0a ed [2] 35 f1 }

  condition:
    any of them
}