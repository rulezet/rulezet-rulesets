rule TTP_XOR_WriteProcessMemory_62dc {
  strings:
    $key_62dc = { 35 ae [2] 07 8c [2] 01 b9 [2] 2f b9 [2] 10 a5 }

  condition:
    any of them
}