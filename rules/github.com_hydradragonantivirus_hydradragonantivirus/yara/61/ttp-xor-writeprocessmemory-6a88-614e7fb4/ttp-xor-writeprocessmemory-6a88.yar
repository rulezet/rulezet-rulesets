rule TTP_XOR_WriteProcessMemory_6a88 {
  strings:
    $key_6a88 = { 3d fa [2] 0f d8 [2] 09 ed [2] 27 ed [2] 18 f1 }

  condition:
    any of them
}