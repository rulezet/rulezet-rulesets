rule TTP_XOR_WriteProcessMemory_f66f {
  strings:
    $key_f66f = { a1 1d [2] 93 3f [2] 95 0a [2] bb 0a [2] 84 16 }

  condition:
    any of them
}