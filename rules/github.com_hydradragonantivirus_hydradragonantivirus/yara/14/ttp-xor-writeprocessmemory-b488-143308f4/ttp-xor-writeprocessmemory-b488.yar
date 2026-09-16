rule TTP_XOR_WriteProcessMemory_b488 {
  strings:
    $key_b488 = { e3 fa [2] d1 d8 [2] d7 ed [2] f9 ed [2] c6 f1 }

  condition:
    any of them
}