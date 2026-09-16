rule TTP_XOR_WriteProcessMemory_f25a {
  strings:
    $key_f25a = { a5 28 [2] 97 0a [2] 91 3f [2] bf 3f [2] 80 23 }

  condition:
    any of them
}