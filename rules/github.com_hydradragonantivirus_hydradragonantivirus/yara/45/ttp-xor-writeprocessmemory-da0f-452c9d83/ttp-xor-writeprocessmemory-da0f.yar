rule TTP_XOR_WriteProcessMemory_da0f {
  strings:
    $key_da0f = { 8d 7d [2] bf 5f [2] b9 6a [2] 97 6a [2] a8 76 }

  condition:
    any of them
}