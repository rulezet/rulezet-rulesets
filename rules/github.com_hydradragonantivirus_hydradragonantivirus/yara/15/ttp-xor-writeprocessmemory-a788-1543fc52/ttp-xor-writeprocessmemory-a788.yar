rule TTP_XOR_WriteProcessMemory_a788 {
  strings:
    $key_a788 = { f0 fa [2] c2 d8 [2] c4 ed [2] ea ed [2] d5 f1 }

  condition:
    any of them
}