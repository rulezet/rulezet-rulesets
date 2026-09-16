rule TTP_XOR_WriteProcessMemory_33dc {
  strings:
    $key_33dc = { 64 ae [2] 56 8c [2] 50 b9 [2] 7e b9 [2] 41 a5 }

  condition:
    any of them
}