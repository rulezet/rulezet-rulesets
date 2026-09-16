rule TTP_XOR_WriteProcessMemory_f2b0 {
  strings:
    $key_f2b0 = { a5 c2 [2] 97 e0 [2] 91 d5 [2] bf d5 [2] 80 c9 }

  condition:
    any of them
}