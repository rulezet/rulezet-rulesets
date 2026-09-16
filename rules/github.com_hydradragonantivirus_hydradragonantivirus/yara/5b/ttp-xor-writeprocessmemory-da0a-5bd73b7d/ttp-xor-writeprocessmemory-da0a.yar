rule TTP_XOR_WriteProcessMemory_da0a {
  strings:
    $key_da0a = { 8d 78 [2] bf 5a [2] b9 6f [2] 97 6f [2] a8 73 }

  condition:
    any of them
}