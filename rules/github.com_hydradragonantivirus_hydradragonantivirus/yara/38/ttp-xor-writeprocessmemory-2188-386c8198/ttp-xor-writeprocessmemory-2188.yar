rule TTP_XOR_WriteProcessMemory_2188 {
  strings:
    $key_2188 = { 76 fa [2] 44 d8 [2] 42 ed [2] 6c ed [2] 53 f1 }

  condition:
    any of them
}