rule TTP_XOR_WriteProcessMemory_f20d {
  strings:
    $key_f20d = { a5 7f [2] 97 5d [2] 91 68 [2] bf 68 [2] 80 74 }

  condition:
    any of them
}