rule TTP_XOR_WriteProcessMemory_f27e {
  strings:
    $key_f27e = { a5 0c [2] 97 2e [2] 91 1b [2] bf 1b [2] 80 07 }

  condition:
    any of them
}