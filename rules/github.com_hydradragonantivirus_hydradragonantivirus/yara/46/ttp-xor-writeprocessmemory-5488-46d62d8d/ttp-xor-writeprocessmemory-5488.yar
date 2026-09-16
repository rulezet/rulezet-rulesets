rule TTP_XOR_WriteProcessMemory_5488 {
  strings:
    $key_5488 = { 03 fa [2] 31 d8 [2] 37 ed [2] 19 ed [2] 26 f1 }

  condition:
    any of them
}