rule TTP_XOR_WriteProcessMemory_f3dc {
  strings:
    $key_f3dc = { a4 ae [2] 96 8c [2] 90 b9 [2] be b9 [2] 81 a5 }

  condition:
    any of them
}