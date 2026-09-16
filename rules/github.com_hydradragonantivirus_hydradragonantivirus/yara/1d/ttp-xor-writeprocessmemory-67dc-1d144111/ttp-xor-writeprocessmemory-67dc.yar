rule TTP_XOR_WriteProcessMemory_67dc {
  strings:
    $key_67dc = { 30 ae [2] 02 8c [2] 04 b9 [2] 2a b9 [2] 15 a5 }

  condition:
    any of them
}