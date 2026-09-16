rule TTP_XOR_WriteProcessMemory_3888 {
  strings:
    $key_3888 = { 6f fa [2] 5d d8 [2] 5b ed [2] 75 ed [2] 4a f1 }

  condition:
    any of them
}