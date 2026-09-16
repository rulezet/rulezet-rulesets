rule TTP_XOR_WriteProcessMemory_da0b {
  strings:
    $key_da0b = { 8d 79 [2] bf 5b [2] b9 6e [2] 97 6e [2] a8 72 }

  condition:
    any of them
}