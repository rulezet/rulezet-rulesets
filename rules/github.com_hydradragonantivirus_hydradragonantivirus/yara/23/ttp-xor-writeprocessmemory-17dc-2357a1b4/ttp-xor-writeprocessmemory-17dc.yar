rule TTP_XOR_WriteProcessMemory_17dc {
  strings:
    $key_17dc = { 40 ae [2] 72 8c [2] 74 b9 [2] 5a b9 [2] 65 a5 }

  condition:
    any of them
}