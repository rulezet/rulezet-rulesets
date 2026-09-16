rule TTP_XOR_WriteProcessMemory_7a88 {
  strings:
    $key_7a88 = { 2d fa [2] 1f d8 [2] 19 ed [2] 37 ed [2] 08 f1 }

  condition:
    any of them
}