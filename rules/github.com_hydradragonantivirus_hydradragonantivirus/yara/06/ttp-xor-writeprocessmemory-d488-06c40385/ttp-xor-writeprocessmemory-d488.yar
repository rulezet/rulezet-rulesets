rule TTP_XOR_WriteProcessMemory_d488 {
  strings:
    $key_d488 = { 83 fa [2] b1 d8 [2] b7 ed [2] 99 ed [2] a6 f1 }

  condition:
    any of them
}