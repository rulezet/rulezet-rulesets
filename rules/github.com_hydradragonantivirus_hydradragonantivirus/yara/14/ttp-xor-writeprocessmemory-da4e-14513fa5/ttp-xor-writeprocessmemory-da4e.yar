rule TTP_XOR_WriteProcessMemory_da4e {
  strings:
    $key_da4e = { 8d 3c [2] bf 1e [2] b9 2b [2] 97 2b [2] a8 37 }

  condition:
    any of them
}