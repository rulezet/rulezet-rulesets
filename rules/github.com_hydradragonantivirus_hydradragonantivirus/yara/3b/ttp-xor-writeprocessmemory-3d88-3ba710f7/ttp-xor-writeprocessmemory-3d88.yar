rule TTP_XOR_WriteProcessMemory_3d88 {
  strings:
    $key_3d88 = { 6a fa [2] 58 d8 [2] 5e ed [2] 70 ed [2] 4f f1 }

  condition:
    any of them
}