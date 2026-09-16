rule TTP_XOR_WriteProcessMemory_1788 {
  strings:
    $key_1788 = { 40 fa [2] 72 d8 [2] 74 ed [2] 5a ed [2] 65 f1 }

  condition:
    any of them
}