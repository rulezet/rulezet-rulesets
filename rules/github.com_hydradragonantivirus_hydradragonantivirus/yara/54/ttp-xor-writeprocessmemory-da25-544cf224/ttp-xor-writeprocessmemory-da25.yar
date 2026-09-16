rule TTP_XOR_WriteProcessMemory_da25 {
  strings:
    $key_da25 = { 8d 57 [2] bf 75 [2] b9 40 [2] 97 40 [2] a8 5c }

  condition:
    any of them
}