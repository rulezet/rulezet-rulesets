rule TTP_XOR_WriteProcessMemory_f212 {
  strings:
    $key_f212 = { a5 60 [2] 97 42 [2] 91 77 [2] bf 77 [2] 80 6b }

  condition:
    any of them
}