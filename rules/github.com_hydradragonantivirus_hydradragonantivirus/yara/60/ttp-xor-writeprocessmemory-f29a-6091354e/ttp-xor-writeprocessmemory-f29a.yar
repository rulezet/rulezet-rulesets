rule TTP_XOR_WriteProcessMemory_f29a {
  strings:
    $key_f29a = { a5 e8 [2] 97 ca [2] 91 ff [2] bf ff [2] 80 e3 }

  condition:
    any of them
}