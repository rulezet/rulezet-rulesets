rule TTP_XOR_WriteProcessMemory_f29d {
  strings:
    $key_f29d = { a5 ef [2] 97 cd [2] 91 f8 [2] bf f8 [2] 80 e4 }

  condition:
    any of them
}