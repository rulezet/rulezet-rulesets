rule TTP_XOR_WriteProcessMemory_d188 {
  strings:
    $key_d188 = { 86 fa [2] b4 d8 [2] b2 ed [2] 9c ed [2] a3 f1 }

  condition:
    any of them
}