rule TTP_XOR_WriteProcessMemory_2388 {
  strings:
    $key_2388 = { 74 fa [2] 46 d8 [2] 40 ed [2] 6e ed [2] 51 f1 }

  condition:
    any of them
}