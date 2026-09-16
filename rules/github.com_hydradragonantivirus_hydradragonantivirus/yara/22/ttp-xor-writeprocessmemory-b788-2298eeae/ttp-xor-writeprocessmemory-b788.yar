rule TTP_XOR_WriteProcessMemory_b788 {
  strings:
    $key_b788 = { e0 fa [2] d2 d8 [2] d4 ed [2] fa ed [2] c5 f1 }

  condition:
    any of them
}