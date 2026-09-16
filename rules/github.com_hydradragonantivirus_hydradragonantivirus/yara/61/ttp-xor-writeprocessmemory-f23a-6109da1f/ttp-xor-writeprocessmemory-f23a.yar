rule TTP_XOR_WriteProcessMemory_f23a {
  strings:
    $key_f23a = { a5 48 [2] 97 6a [2] 91 5f [2] bf 5f [2] 80 43 }

  condition:
    any of them
}