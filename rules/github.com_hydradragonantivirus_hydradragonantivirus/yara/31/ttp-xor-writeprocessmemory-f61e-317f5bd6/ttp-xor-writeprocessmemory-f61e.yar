rule TTP_XOR_WriteProcessMemory_f61e {
  strings:
    $key_f61e = { a1 6c [2] 93 4e [2] 95 7b [2] bb 7b [2] 84 67 }

  condition:
    any of them
}