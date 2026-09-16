rule TTP_XOR_WriteProcessMemory_b388 {
  strings:
    $key_b388 = { e4 fa [2] d6 d8 [2] d0 ed [2] fe ed [2] c1 f1 }

  condition:
    any of them
}