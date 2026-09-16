rule TTP_XOR_WriteProcessMemory_f62e {
  strings:
    $key_f62e = { a1 5c [2] 93 7e [2] 95 4b [2] bb 4b [2] 84 57 }

  condition:
    any of them
}