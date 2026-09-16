rule TTP_XOR_WriteProcessMemory_f43e {
  strings:
    $key_f43e = { a3 4c [2] 91 6e [2] 97 5b [2] b9 5b [2] 86 47 }

  condition:
    any of them
}