rule TTP_XOR_WriteProcessMemory_e588 {
  strings:
    $key_e588 = { b2 fa [2] 80 d8 [2] 86 ed [2] a8 ed [2] 97 f1 }

  condition:
    any of them
}