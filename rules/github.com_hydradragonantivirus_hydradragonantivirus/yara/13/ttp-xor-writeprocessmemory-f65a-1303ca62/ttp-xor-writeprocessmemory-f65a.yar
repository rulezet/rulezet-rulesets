rule TTP_XOR_WriteProcessMemory_f65a {
  strings:
    $key_f65a = { a1 28 [2] 93 0a [2] 95 3f [2] bb 3f [2] 84 23 }

  condition:
    any of them
}