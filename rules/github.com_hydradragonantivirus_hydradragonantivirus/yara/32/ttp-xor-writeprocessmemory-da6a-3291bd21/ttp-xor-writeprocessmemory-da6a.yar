rule TTP_XOR_WriteProcessMemory_da6a {
  strings:
    $key_da6a = { 8d 18 [2] bf 3a [2] b9 0f [2] 97 0f [2] a8 13 }

  condition:
    any of them
}