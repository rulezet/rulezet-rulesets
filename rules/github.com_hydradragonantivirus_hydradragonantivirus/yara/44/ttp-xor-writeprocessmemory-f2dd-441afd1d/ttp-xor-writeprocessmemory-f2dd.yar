rule TTP_XOR_WriteProcessMemory_f2dd {
  strings:
    $key_f2dd = { a5 af [2] 97 8d [2] 91 b8 [2] bf b8 [2] 80 a4 }

  condition:
    any of them
}