rule TTP_XOR_WriteProcessMemory_21dc {
  strings:
    $key_21dc = { 76 ae [2] 44 8c [2] 42 b9 [2] 6c b9 [2] 53 a5 }

  condition:
    any of them
}