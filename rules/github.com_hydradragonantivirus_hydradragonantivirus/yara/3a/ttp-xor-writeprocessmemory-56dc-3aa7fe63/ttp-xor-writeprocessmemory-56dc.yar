rule TTP_XOR_WriteProcessMemory_56dc {
  strings:
    $key_56dc = { 01 ae [2] 33 8c [2] 35 b9 [2] 1b b9 [2] 24 a5 }

  condition:
    any of them
}