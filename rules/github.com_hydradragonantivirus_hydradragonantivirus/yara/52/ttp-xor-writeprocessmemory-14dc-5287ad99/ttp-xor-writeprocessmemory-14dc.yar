rule TTP_XOR_WriteProcessMemory_14dc {
  strings:
    $key_14dc = { 43 ae [2] 71 8c [2] 77 b9 [2] 59 b9 [2] 66 a5 }

  condition:
    any of them
}