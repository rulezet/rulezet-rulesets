rule TTP_XOR_WriteProcessMemory_da7a {
  strings:
    $key_da7a = { 8d 08 [2] bf 2a [2] b9 1f [2] 97 1f [2] a8 03 }

  condition:
    any of them
}