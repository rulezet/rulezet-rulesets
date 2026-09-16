rule TTP_XOR_WriteProcessMemory_2288 {
  strings:
    $key_2288 = { 75 fa [2] 47 d8 [2] 41 ed [2] 6f ed [2] 50 f1 }

  condition:
    any of them
}