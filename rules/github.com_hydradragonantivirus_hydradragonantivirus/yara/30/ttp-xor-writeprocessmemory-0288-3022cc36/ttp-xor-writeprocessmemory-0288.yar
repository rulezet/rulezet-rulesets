rule TTP_XOR_WriteProcessMemory_0288 {
  strings:
    $key_0288 = { 55 fa [2] 67 d8 [2] 61 ed [2] 4f ed [2] 70 f1 }

  condition:
    any of them
}