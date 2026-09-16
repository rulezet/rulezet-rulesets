rule TTP_XOR_WriteProcessMemory_f0dd {
  strings:
    $key_f0dd = { a7 af [2] 95 8d [2] 93 b8 [2] bd b8 [2] 82 a4 }

  condition:
    any of them
}