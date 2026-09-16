rule TTP_XOR_WriteProcessMemory_1d88 {
  strings:
    $key_1d88 = { 4a fa [2] 78 d8 [2] 7e ed [2] 50 ed [2] 6f f1 }

  condition:
    any of them
}