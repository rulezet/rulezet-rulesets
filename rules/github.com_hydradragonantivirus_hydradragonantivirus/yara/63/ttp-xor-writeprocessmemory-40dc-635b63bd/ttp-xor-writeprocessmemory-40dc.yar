rule TTP_XOR_WriteProcessMemory_40dc {
  strings:
    $key_40dc = { 17 ae [2] 25 8c [2] 23 b9 [2] 0d b9 [2] 32 a5 }

  condition:
    any of them
}