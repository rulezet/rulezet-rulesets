rule TTP_XOR_WriteProcessMemory_f768 {
  strings:
    $key_f768 = { a0 1a [2] 92 38 [2] 94 0d [2] ba 0d [2] 85 11 }

  condition:
    any of them
}