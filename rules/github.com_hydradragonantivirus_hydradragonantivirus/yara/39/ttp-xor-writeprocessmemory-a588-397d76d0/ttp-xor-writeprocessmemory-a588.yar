rule TTP_XOR_WriteProcessMemory_a588 {
  strings:
    $key_a588 = { f2 fa [2] c0 d8 [2] c6 ed [2] e8 ed [2] d7 f1 }

  condition:
    any of them
}