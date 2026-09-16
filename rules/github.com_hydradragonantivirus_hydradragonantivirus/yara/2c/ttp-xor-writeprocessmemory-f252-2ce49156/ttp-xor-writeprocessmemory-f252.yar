rule TTP_XOR_WriteProcessMemory_f252 {
  strings:
    $key_f252 = { a5 20 [2] 97 02 [2] 91 37 [2] bf 37 [2] 80 2b }

  condition:
    any of them
}