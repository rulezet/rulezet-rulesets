rule TTP_XOR_WriteProcessMemory_f7dc {
  strings:
    $key_f7dc = { a0 ae [2] 92 8c [2] 94 b9 [2] ba b9 [2] 85 a5 }

  condition:
    any of them
}