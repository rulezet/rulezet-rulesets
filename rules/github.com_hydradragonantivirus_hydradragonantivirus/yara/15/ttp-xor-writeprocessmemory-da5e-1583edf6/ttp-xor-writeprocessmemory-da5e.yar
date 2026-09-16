rule TTP_XOR_WriteProcessMemory_da5e {
  strings:
    $key_da5e = { 8d 2c [2] bf 0e [2] b9 3b [2] 97 3b [2] a8 27 }

  condition:
    any of them
}