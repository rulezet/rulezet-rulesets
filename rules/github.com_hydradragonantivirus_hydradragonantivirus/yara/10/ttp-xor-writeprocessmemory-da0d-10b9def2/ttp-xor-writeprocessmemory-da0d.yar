rule TTP_XOR_WriteProcessMemory_da0d {
  strings:
    $key_da0d = { 8d 7f [2] bf 5d [2] b9 68 [2] 97 68 [2] a8 74 }

  condition:
    any of them
}