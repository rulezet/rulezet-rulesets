rule TTP_XOR_WriteProcessMemory_f27c {
  strings:
    $key_f27c = { a5 0e [2] 97 2c [2] 91 19 [2] bf 19 [2] 80 05 }

  condition:
    any of them
}