rule TTP_XOR_WriteProcessMemory_47dc {
  strings:
    $key_47dc = { 10 ae [2] 22 8c [2] 24 b9 [2] 0a b9 [2] 35 a5 }

  condition:
    any of them
}