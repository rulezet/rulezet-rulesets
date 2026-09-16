rule TTP_XOR_WriteProcessMemory_da6e {
  strings:
    $key_da6e = { 8d 1c [2] bf 3e [2] b9 0b [2] 97 0b [2] a8 17 }

  condition:
    any of them
}