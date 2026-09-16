rule TTP_XOR_WriteProcessMemory_f24c {
  strings:
    $key_f24c = { a5 3e [2] 97 1c [2] 91 29 [2] bf 29 [2] 80 35 }

  condition:
    any of them
}