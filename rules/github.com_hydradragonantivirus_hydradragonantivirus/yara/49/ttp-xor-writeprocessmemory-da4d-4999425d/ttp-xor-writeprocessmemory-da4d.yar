rule TTP_XOR_WriteProcessMemory_da4d {
  strings:
    $key_da4d = { 8d 3f [2] bf 1d [2] b9 28 [2] 97 28 [2] a8 34 }

  condition:
    any of them
}