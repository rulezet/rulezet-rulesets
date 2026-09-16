rule TTP_XOR_WriteProcessMemory_3588 {
  strings:
    $key_3588 = { 62 fa [2] 50 d8 [2] 56 ed [2] 78 ed [2] 47 f1 }

  condition:
    any of them
}