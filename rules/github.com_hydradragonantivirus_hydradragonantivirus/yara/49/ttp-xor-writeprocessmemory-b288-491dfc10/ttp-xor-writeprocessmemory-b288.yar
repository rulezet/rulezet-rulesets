rule TTP_XOR_WriteProcessMemory_b288 {
  strings:
    $key_b288 = { e5 fa [2] d7 d8 [2] d1 ed [2] ff ed [2] c0 f1 }

  condition:
    any of them
}