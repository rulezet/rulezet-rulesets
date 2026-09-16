rule TTP_XOR_WriteProcessMemory_e388 {
  strings:
    $key_e388 = { b4 fa [2] 86 d8 [2] 80 ed [2] ae ed [2] 91 f1 }

  condition:
    any of them
}