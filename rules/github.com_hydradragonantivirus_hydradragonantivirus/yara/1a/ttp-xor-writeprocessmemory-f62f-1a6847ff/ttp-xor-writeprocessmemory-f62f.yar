rule TTP_XOR_WriteProcessMemory_f62f {
  strings:
    $key_f62f = { a1 5d [2] 93 7f [2] 95 4a [2] bb 4a [2] 84 56 }

  condition:
    any of them
}