rule TTP_XOR_WriteProcessMemory_f27f {
  strings:
    $key_f27f = { a5 0d [2] 97 2f [2] 91 1a [2] bf 1a [2] 80 06 }

  condition:
    any of them
}