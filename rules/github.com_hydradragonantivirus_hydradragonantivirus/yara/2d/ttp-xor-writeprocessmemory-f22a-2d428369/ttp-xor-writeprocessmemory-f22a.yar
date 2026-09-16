rule TTP_XOR_WriteProcessMemory_f22a {
  strings:
    $key_f22a = { a5 58 [2] 97 7a [2] 91 4f [2] bf 4f [2] 80 53 }

  condition:
    any of them
}