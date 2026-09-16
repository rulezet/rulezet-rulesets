rule TTP_XOR_WriteProcessMemory_f20f {
  strings:
    $key_f20f = { a5 7d [2] 97 5f [2] 91 6a [2] bf 6a [2] 80 76 }

  condition:
    any of them
}