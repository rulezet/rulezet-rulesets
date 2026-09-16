rule TTP_XOR_WriteProcessMemory_5088 {
  strings:
    $key_5088 = { 07 fa [2] 35 d8 [2] 33 ed [2] 1d ed [2] 22 f1 }

  condition:
    any of them
}