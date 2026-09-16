rule TTP_XOR_WriteProcessMemory_f72f {
  strings:
    $key_f72f = { a0 5d [2] 92 7f [2] 94 4a [2] ba 4a [2] 85 56 }

  condition:
    any of them
}