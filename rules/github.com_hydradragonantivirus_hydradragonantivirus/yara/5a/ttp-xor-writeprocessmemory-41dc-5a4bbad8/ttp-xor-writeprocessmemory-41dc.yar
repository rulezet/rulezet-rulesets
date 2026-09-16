rule TTP_XOR_WriteProcessMemory_41dc {
  strings:
    $key_41dc = { 16 ae [2] 24 8c [2] 22 b9 [2] 0c b9 [2] 33 a5 }

  condition:
    any of them
}