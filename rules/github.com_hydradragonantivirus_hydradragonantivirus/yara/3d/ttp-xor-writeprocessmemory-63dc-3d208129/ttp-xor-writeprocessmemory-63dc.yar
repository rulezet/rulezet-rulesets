rule TTP_XOR_WriteProcessMemory_63dc {
  strings:
    $key_63dc = { 34 ae [2] 06 8c [2] 00 b9 [2] 2e b9 [2] 11 a5 }

  condition:
    any of them
}