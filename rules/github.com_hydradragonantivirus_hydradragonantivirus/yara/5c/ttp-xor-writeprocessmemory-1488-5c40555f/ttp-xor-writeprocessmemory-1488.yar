rule TTP_XOR_WriteProcessMemory_1488 {
  strings:
    $key_1488 = { 43 fa [2] 71 d8 [2] 77 ed [2] 59 ed [2] 66 f1 }

  condition:
    any of them
}