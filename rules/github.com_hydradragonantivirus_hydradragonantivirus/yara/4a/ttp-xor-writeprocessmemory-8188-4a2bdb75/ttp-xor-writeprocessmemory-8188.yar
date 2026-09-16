rule TTP_XOR_WriteProcessMemory_8188 {
  strings:
    $key_8188 = { d6 fa [2] e4 d8 [2] e2 ed [2] cc ed [2] f3 f1 }

  condition:
    any of them
}