rule TTP_XOR_WriteProcessMemory_da1a {
  strings:
    $key_da1a = { 8d 68 [2] bf 4a [2] b9 7f [2] 97 7f [2] a8 63 }

  condition:
    any of them
}