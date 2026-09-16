rule TTP_XOR_WriteProcessMemory_da55 {
  strings:
    $key_da55 = { 8d 27 [2] bf 05 [2] b9 30 [2] 97 30 [2] a8 2c }

  condition:
    any of them
}