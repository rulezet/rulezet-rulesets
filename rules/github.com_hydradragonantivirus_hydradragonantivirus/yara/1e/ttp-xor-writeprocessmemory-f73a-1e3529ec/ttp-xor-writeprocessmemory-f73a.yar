rule TTP_XOR_WriteProcessMemory_f73a {
  strings:
    $key_f73a = { a0 48 [2] 92 6a [2] 94 5f [2] ba 5f [2] 85 43 }

  condition:
    any of them
}