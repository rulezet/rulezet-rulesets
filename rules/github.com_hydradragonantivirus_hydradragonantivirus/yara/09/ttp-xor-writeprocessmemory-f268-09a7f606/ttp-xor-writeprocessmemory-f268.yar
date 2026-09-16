rule TTP_XOR_WriteProcessMemory_f268 {
  strings:
    $key_f268 = { a5 1a [2] 97 38 [2] 91 0d [2] bf 0d [2] 80 11 }

  condition:
    any of them
}