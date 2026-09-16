rule TTP_XOR_WriteProcessMemory_da05 {
  strings:
    $key_da05 = { 8d 77 [2] bf 55 [2] b9 60 [2] 97 60 [2] a8 7c }

  condition:
    any of them
}