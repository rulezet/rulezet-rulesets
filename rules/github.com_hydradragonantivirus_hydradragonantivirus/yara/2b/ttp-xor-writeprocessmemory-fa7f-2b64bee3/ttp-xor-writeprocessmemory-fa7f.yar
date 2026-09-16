rule TTP_XOR_WriteProcessMemory_fa7f {
  strings:
    $key_fa7f = { ad 0d [2] 9f 2f [2] 99 1a [2] b7 1a [2] 88 06 }

  condition:
    any of them
}