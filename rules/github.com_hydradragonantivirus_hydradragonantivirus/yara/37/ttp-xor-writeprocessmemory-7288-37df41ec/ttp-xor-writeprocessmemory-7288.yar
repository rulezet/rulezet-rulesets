rule TTP_XOR_WriteProcessMemory_7288 {
  strings:
    $key_7288 = { 25 fa [2] 17 d8 [2] 11 ed [2] 3f ed [2] 00 f1 }

  condition:
    any of them
}