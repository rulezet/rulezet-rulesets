rule TTP_XOR_WriteProcessMemory_2588 {
  strings:
    $key_2588 = { 72 fa [2] 40 d8 [2] 46 ed [2] 68 ed [2] 57 f1 }

  condition:
    any of them
}