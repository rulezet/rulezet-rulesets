rule TTP_XOR_WriteProcessMemory_0588 {
  strings:
    $key_0588 = { 52 fa [2] 60 d8 [2] 66 ed [2] 48 ed [2] 77 f1 }

  condition:
    any of them
}