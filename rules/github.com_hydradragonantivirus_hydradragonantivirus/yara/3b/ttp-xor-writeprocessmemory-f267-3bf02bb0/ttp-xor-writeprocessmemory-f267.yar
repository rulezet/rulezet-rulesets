rule TTP_XOR_WriteProcessMemory_f267 {
  strings:
    $key_f267 = { a5 15 [2] 97 37 [2] 91 02 [2] bf 02 [2] 80 1e }

  condition:
    any of them
}