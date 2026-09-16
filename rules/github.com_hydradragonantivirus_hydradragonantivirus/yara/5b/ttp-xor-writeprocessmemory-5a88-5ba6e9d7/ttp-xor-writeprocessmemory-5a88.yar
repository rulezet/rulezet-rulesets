rule TTP_XOR_WriteProcessMemory_5a88 {
  strings:
    $key_5a88 = { 0d fa [2] 3f d8 [2] 39 ed [2] 17 ed [2] 28 f1 }

  condition:
    any of them
}