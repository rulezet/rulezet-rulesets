rule TTP_XOR_WriteProcessMemory_f2ea {
  strings:
    $key_f2ea = { a5 98 [2] 97 ba [2] 91 8f [2] bf 8f [2] 80 93 }

  condition:
    any of them
}