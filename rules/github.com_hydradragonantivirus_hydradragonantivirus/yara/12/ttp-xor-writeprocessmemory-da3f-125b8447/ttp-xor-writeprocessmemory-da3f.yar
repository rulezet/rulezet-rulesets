rule TTP_XOR_WriteProcessMemory_da3f {
  strings:
    $key_da3f = { 8d 4d [2] bf 6f [2] b9 5a [2] 97 5a [2] a8 46 }

  condition:
    any of them
}