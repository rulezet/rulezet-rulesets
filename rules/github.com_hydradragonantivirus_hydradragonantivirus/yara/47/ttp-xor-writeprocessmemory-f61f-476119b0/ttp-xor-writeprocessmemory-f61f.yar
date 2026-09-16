rule TTP_XOR_WriteProcessMemory_f61f {
  strings:
    $key_f61f = { a1 6d [2] 93 4f [2] 95 7a [2] bb 7a [2] 84 66 }

  condition:
    any of them
}