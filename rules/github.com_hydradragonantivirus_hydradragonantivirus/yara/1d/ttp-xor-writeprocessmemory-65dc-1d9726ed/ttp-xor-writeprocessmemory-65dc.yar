rule TTP_XOR_WriteProcessMemory_65dc {
  strings:
    $key_65dc = { 32 ae [2] 00 8c [2] 06 b9 [2] 28 b9 [2] 17 a5 }

  condition:
    any of them
}