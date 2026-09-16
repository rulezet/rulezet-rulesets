rule TTP_XOR_WriteProcessMemory_f75a {
  strings:
    $key_f75a = { a0 28 [2] 92 0a [2] 94 3f [2] ba 3f [2] 85 23 }

  condition:
    any of them
}