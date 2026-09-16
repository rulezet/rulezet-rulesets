rule TTP_XOR_WriteProcessMemory_f24d {
  strings:
    $key_f24d = { a5 3f [2] 97 1d [2] 91 28 [2] bf 28 [2] 80 34 }

  condition:
    any of them
}