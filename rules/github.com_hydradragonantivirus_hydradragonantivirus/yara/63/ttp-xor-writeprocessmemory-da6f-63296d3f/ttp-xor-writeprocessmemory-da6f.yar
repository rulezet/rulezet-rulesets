rule TTP_XOR_WriteProcessMemory_da6f {
  strings:
    $key_da6f = { 8d 1d [2] bf 3f [2] b9 0a [2] 97 0a [2] a8 16 }

  condition:
    any of them
}