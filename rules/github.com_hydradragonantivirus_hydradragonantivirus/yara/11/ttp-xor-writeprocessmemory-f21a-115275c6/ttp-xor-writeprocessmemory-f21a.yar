rule TTP_XOR_WriteProcessMemory_f21a {
  strings:
    $key_f21a = { a5 68 [2] 97 4a [2] 91 7f [2] bf 7f [2] 80 63 }

  condition:
    any of them
}