rule TTP_XOR_WriteProcessMemory_f2dc {
  strings:
    $key_f2dc = { a5 ae [2] 97 8c [2] 91 b9 [2] bf b9 [2] 80 a5 }

  condition:
    any of them
}