rule TTP_XOR_WriteProcessMemory_4888 {
  strings:
    $key_4888 = { 1f fa [2] 2d d8 [2] 2b ed [2] 05 ed [2] 3a f1 }

  condition:
    any of them
}