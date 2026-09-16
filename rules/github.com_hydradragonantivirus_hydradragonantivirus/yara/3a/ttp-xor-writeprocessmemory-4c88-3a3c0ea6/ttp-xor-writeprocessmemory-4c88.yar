rule TTP_XOR_WriteProcessMemory_4c88 {
  strings:
    $key_4c88 = { 1b fa [2] 29 d8 [2] 2f ed [2] 01 ed [2] 3e f1 }

  condition:
    any of them
}