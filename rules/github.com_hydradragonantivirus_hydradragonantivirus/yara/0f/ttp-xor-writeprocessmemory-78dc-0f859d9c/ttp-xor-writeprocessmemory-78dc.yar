rule TTP_XOR_WriteProcessMemory_78dc {
  strings:
    $key_78dc = { 2f ae [2] 1d 8c [2] 1b b9 [2] 35 b9 [2] 0a a5 }

  condition:
    any of them
}