rule TTP_XOR_WriteProcessMemory_f24a {
  strings:
    $key_f24a = { a5 38 [2] 97 1a [2] 91 2f [2] bf 2f [2] 80 33 }

  condition:
    any of them
}