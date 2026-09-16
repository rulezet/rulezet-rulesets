rule TTP_XOR_WriteProcessMemory_3488 {
  strings:
    $key_3488 = { 63 fa [2] 51 d8 [2] 57 ed [2] 79 ed [2] 46 f1 }

  condition:
    any of them
}