rule TTP_XOR_WriteProcessMemory_f7dd {
  strings:
    $key_f7dd = { a0 af [2] 92 8d [2] 94 b8 [2] ba b8 [2] 85 a4 }

  condition:
    any of them
}