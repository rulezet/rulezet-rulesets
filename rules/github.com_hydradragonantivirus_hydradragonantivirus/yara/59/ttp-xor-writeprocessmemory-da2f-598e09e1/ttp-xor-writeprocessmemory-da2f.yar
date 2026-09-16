rule TTP_XOR_WriteProcessMemory_da2f {
  strings:
    $key_da2f = { 8d 5d [2] bf 7f [2] b9 4a [2] 97 4a [2] a8 56 }

  condition:
    any of them
}