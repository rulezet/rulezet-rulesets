rule TTP_XOR_WriteProcessMemory_f70a {
  strings:
    $key_f70a = { a0 78 [2] 92 5a [2] 94 6f [2] ba 6f [2] 85 73 }

  condition:
    any of them
}