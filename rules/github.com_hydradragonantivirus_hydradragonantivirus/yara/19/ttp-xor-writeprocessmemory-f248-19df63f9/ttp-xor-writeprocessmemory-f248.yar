rule TTP_XOR_WriteProcessMemory_f248 {
  strings:
    $key_f248 = { a5 3a [2] 97 18 [2] 91 2d [2] bf 2d [2] 80 31 }

  condition:
    any of them
}