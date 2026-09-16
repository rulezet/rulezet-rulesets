rule TTP_XOR_WriteProcessMemory_f2f8 {
  strings:
    $key_f2f8 = { a5 8a [2] 97 a8 [2] 91 9d [2] bf 9d [2] 80 81 }

  condition:
    any of them
}