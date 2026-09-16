rule TTP_XOR_WriteProcessMemory_da6b {
  strings:
    $key_da6b = { 8d 19 [2] bf 3b [2] b9 0e [2] 97 0e [2] a8 12 }

  condition:
    any of them
}