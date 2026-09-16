rule TTP_XOR_WriteProcessMemory_da7c {
  strings:
    $key_da7c = { 8d 0e [2] bf 2c [2] b9 19 [2] 97 19 [2] a8 05 }

  condition:
    any of them
}