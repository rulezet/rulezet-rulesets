rule TTP_XOR_WriteProcessMemory_f7fc {
  strings:
    $key_f7fc = { a0 8e [2] 92 ac [2] 94 99 [2] ba 99 [2] 85 85 }

  condition:
    any of them
}