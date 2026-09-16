rule TTP_XOR_WriteProcessMemory_0d88 {
  strings:
    $key_0d88 = { 5a fa [2] 68 d8 [2] 6e ed [2] 40 ed [2] 7f f1 }

  condition:
    any of them
}