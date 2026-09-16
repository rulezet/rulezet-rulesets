rule TTP_XOR_WriteProcessMemory_f41e {
  strings:
    $key_f41e = { a3 6c [2] 91 4e [2] 97 7b [2] b9 7b [2] 86 67 }

  condition:
    any of them
}