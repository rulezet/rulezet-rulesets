rule TTP_XOR_WriteProcessMemory_f2a2 {
  strings:
    $key_f2a2 = { a5 d0 [2] 97 f2 [2] 91 c7 [2] bf c7 [2] 80 db }

  condition:
    any of them
}