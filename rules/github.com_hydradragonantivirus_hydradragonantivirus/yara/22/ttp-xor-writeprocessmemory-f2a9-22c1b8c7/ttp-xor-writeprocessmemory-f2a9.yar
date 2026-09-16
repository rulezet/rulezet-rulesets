rule TTP_XOR_WriteProcessMemory_f2a9 {
  strings:
    $key_f2a9 = { a5 db [2] 97 f9 [2] 91 cc [2] bf cc [2] 80 d0 }

  condition:
    any of them
}