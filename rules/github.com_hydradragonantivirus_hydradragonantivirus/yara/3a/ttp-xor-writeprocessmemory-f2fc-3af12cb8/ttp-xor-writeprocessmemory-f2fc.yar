rule TTP_XOR_WriteProcessMemory_f2fc {
  strings:
    $key_f2fc = { a5 8e [2] 97 ac [2] 91 99 [2] bf 99 [2] 80 85 }

  condition:
    any of them
}