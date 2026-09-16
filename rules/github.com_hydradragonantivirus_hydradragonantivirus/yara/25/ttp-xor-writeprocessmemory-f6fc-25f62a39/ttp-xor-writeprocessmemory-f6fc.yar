rule TTP_XOR_WriteProcessMemory_f6fc {
  strings:
    $key_f6fc = { a1 8e [2] 93 ac [2] 95 99 [2] bb 99 [2] 84 85 }

  condition:
    any of them
}