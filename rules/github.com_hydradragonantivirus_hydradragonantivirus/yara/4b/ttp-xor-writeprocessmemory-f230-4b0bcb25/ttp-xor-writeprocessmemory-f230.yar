rule TTP_XOR_WriteProcessMemory_f230 {
  strings:
    $key_f230 = { a5 42 [2] 97 60 [2] 91 55 [2] bf 55 [2] 80 49 }

  condition:
    any of them
}