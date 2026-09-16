rule TTP_XOR_WriteProcessMemory_f20a {
  strings:
    $key_f20a = { a5 78 [2] 97 5a [2] 91 6f [2] bf 6f [2] 80 73 }

  condition:
    any of them
}