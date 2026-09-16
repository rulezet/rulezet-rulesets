rule TTP_XOR_WriteProcessMemory_f29c {
  strings:
    $key_f29c = { a5 ee [2] 97 cc [2] 91 f9 [2] bf f9 [2] 80 e5 }

  condition:
    any of them
}