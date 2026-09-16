rule TTP_XOR_WriteProcessMemory_2a88 {
  strings:
    $key_2a88 = { 7d fa [2] 4f d8 [2] 49 ed [2] 67 ed [2] 58 f1 }

  condition:
    any of them
}