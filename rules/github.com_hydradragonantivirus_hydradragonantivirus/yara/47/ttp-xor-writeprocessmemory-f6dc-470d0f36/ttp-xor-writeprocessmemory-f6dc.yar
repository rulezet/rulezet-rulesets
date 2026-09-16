rule TTP_XOR_WriteProcessMemory_f6dc {
  strings:
    $key_f6dc = { a1 ae [2] 93 8c [2] 95 b9 [2] bb b9 [2] 84 a5 }

  condition:
    any of them
}