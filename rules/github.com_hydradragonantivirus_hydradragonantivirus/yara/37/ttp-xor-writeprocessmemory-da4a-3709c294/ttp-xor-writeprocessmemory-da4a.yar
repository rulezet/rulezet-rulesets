rule TTP_XOR_WriteProcessMemory_da4a {
  strings:
    $key_da4a = { 8d 38 [2] bf 1a [2] b9 2f [2] 97 2f [2] a8 33 }

  condition:
    any of them
}