rule TTP_XOR_WriteProcessMemory_d288 {
  strings:
    $key_d288 = { 85 fa [2] b7 d8 [2] b1 ed [2] 9f ed [2] a0 f1 }

  condition:
    any of them
}