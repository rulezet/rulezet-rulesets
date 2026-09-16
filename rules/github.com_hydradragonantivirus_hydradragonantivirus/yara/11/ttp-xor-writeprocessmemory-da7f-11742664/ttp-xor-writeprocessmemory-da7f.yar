rule TTP_XOR_WriteProcessMemory_da7f {
  strings:
    $key_da7f = { 8d 0d [2] bf 2f [2] b9 1a [2] 97 1a [2] a8 06 }

  condition:
    any of them
}