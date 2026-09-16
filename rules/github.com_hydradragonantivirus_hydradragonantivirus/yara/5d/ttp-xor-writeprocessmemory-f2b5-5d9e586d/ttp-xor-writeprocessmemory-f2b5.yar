rule TTP_XOR_WriteProcessMemory_f2b5 {
  strings:
    $key_f2b5 = { a5 c7 [2] 97 e5 [2] 91 d0 [2] bf d0 [2] 80 cc }

  condition:
    any of them
}