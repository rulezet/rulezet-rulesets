rule TTP_XOR_WriteProcessMemory_f20e {
  strings:
    $key_f20e = { a5 7c [2] 97 5e [2] 91 6b [2] bf 6b [2] 80 77 }

  condition:
    any of them
}