rule TTP_XOR_WriteProcessMemory_1588 {
  strings:
    $key_1588 = { 42 fa [2] 70 d8 [2] 76 ed [2] 58 ed [2] 67 f1 }

  condition:
    any of them
}