rule TTP_XOR_WriteProcessMemory_f25e {
  strings:
    $key_f25e = { a5 2c [2] 97 0e [2] 91 3b [2] bf 3b [2] 80 27 }

  condition:
    any of them
}