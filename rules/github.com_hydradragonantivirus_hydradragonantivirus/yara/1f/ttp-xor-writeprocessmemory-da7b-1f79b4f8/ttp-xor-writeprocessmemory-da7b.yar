rule TTP_XOR_WriteProcessMemory_da7b {
  strings:
    $key_da7b = { 8d 09 [2] bf 2b [2] b9 1e [2] 97 1e [2] a8 02 }

  condition:
    any of them
}