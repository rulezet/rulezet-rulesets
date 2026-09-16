rule TTP_XOR_WriteProcessMemory_e53e {
  strings:
    $key_e53e = { b2 4c [2] 80 6e [2] 86 5b [2] a8 5b [2] 97 47 }

  condition:
    any of them
}