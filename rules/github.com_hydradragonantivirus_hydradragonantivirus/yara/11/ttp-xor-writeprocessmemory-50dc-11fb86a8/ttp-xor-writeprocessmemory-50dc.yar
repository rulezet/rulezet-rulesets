rule TTP_XOR_WriteProcessMemory_50dc {
  strings:
    $key_50dc = { 07 ae [2] 35 8c [2] 33 b9 [2] 1d b9 [2] 22 a5 }

  condition:
    any of them
}