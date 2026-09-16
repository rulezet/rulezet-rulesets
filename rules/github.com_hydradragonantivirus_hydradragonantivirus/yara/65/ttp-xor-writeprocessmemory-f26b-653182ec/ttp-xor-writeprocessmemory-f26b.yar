rule TTP_XOR_WriteProcessMemory_f26b {
  strings:
    $key_f26b = { a5 19 [2] 97 3b [2] 91 0e [2] bf 0e [2] 80 12 }

  condition:
    any of them
}