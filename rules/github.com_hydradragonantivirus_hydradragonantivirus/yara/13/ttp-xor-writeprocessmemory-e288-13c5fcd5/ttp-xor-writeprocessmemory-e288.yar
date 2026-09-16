rule TTP_XOR_WriteProcessMemory_e288 {
  strings:
    $key_e288 = { b5 fa [2] 87 d8 [2] 81 ed [2] af ed [2] 90 f1 }

  condition:
    any of them
}