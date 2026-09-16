rule TTP_XOR_WriteProcessMemory_f60d {
  strings:
    $key_f60d = { a1 7f [2] 93 5d [2] 95 68 [2] bb 68 [2] 84 74 }

  condition:
    any of them
}