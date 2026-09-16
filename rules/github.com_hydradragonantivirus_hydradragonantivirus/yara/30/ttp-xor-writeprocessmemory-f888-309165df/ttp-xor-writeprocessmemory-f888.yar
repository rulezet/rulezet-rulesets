rule TTP_XOR_WriteProcessMemory_f888 {
  strings:
    $key_f888 = { af fa [2] 9d d8 [2] 9b ed [2] b5 ed [2] 8a f1 }

  condition:
    any of them
}