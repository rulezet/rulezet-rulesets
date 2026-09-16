rule TTP_XOR_WriteProcessMemory_68dc {
  strings:
    $key_68dc = { 3f ae [2] 0d 8c [2] 0b b9 [2] 25 b9 [2] 1a a5 }

  condition:
    any of them
}