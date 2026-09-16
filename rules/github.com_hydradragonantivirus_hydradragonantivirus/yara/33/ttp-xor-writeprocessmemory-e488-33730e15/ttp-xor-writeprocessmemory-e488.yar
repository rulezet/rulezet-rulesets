rule TTP_XOR_WriteProcessMemory_e488 {
  strings:
    $key_e488 = { b3 fa [2] 81 d8 [2] 87 ed [2] a9 ed [2] 96 f1 }

  condition:
    any of them
}