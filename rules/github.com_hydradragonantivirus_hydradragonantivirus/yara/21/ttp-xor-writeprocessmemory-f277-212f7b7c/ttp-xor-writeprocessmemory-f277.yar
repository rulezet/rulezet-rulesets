rule TTP_XOR_WriteProcessMemory_f277 {
  strings:
    $key_f277 = { a5 05 [2] 97 27 [2] 91 12 [2] bf 12 [2] 80 0e }

  condition:
    any of them
}