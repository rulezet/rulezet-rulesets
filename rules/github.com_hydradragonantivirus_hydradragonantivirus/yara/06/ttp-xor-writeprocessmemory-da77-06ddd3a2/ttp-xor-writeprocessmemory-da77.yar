rule TTP_XOR_WriteProcessMemory_da77 {
  strings:
    $key_da77 = { 8d 05 [2] bf 27 [2] b9 12 [2] 97 12 [2] a8 0e }

  condition:
    any of them
}