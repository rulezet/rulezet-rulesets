rule TTP_XOR_WriteProcessMemory_c288 {
  strings:
    $key_c288 = { 95 fa [2] a7 d8 [2] a1 ed [2] 8f ed [2] b0 f1 }

  condition:
    any of them
}