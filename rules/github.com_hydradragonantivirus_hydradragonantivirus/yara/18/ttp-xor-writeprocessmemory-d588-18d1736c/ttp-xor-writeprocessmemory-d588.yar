rule TTP_XOR_WriteProcessMemory_d588 {
  strings:
    $key_d588 = { 82 fa [2] b0 d8 [2] b6 ed [2] 98 ed [2] a7 f1 }

  condition:
    any of them
}