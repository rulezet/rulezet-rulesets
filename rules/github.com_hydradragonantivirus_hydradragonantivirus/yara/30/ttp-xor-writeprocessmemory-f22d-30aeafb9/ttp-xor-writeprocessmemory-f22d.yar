rule TTP_XOR_WriteProcessMemory_f22d {
  strings:
    $key_f22d = { a5 5f [2] 97 7d [2] 91 48 [2] bf 48 [2] 80 54 }

  condition:
    any of them
}