rule TTP_XOR_WriteProcessMemory_3288 {
  strings:
    $key_3288 = { 65 fa [2] 57 d8 [2] 51 ed [2] 7f ed [2] 40 f1 }

  condition:
    any of them
}