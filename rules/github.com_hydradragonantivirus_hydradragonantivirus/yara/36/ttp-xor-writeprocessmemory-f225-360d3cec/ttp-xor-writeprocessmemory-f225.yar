rule TTP_XOR_WriteProcessMemory_f225 {
  strings:
    $key_f225 = { a5 57 [2] 97 75 [2] 91 40 [2] bf 40 [2] 80 5c }

  condition:
    any of them
}