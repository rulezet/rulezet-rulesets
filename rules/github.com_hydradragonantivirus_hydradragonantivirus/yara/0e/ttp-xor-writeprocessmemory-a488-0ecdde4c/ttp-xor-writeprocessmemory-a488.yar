rule TTP_XOR_WriteProcessMemory_a488 {
  strings:
    $key_a488 = { f3 fa [2] c1 d8 [2] c7 ed [2] e9 ed [2] d6 f1 }

  condition:
    any of them
}