rule TTP_XOR_WriteProcessMemory_f2b4 {
  strings:
    $key_f2b4 = { a5 c6 [2] 97 e4 [2] 91 d1 [2] bf d1 [2] 80 cd }

  condition:
    any of them
}