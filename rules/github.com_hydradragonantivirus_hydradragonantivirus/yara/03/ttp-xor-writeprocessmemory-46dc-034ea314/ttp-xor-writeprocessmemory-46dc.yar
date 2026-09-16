rule TTP_XOR_WriteProcessMemory_46dc {
  strings:
    $key_46dc = { 11 ae [2] 23 8c [2] 25 b9 [2] 0b b9 [2] 34 a5 }

  condition:
    any of them
}