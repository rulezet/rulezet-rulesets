rule TTP_XOR_WriteProcessMemory_f21d {
  strings:
    $key_f21d = { a5 6f [2] 97 4d [2] 91 78 [2] bf 78 [2] 80 64 }

  condition:
    any of them
}