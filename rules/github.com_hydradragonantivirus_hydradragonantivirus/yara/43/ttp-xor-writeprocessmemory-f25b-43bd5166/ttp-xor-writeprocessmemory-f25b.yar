rule TTP_XOR_WriteProcessMemory_f25b {
  strings:
    $key_f25b = { a5 29 [2] 97 0b [2] 91 3e [2] bf 3e [2] 80 22 }

  condition:
    any of them
}