rule TTP_XOR_WriteProcessMemory_c688 {
  strings:
    $key_c688 = { 91 fa [2] a3 d8 [2] a5 ed [2] 8b ed [2] b4 f1 }

  condition:
    any of them
}