rule TTP_XOR_WriteProcessMemory_b588 {
  strings:
    $key_b588 = { e2 fa [2] d0 d8 [2] d6 ed [2] f8 ed [2] c7 f1 }

  condition:
    any of them
}