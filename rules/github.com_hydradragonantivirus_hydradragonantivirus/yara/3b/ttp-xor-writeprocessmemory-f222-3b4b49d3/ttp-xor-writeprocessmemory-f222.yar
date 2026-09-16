rule TTP_XOR_WriteProcessMemory_f222 {
  strings:
    $key_f222 = { a5 50 [2] 97 72 [2] 91 47 [2] bf 47 [2] 80 5b }

  condition:
    any of them
}