rule TTP_XOR_WriteProcessMemory_f2be {
  strings:
    $key_f2be = { a5 cc [2] 97 ee [2] 91 db [2] bf db [2] 80 c7 }

  condition:
    any of them
}