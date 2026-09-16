rule TTP_XOR_WriteProcessMemory_7788 {
  strings:
    $key_7788 = { 20 fa [2] 12 d8 [2] 14 ed [2] 3a ed [2] 05 f1 }

  condition:
    any of them
}