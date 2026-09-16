rule TTP_XOR_WriteProcessMemory_f778 {
  strings:
    $key_f778 = { a0 0a [2] 92 28 [2] 94 1d [2] ba 1d [2] 85 01 }

  condition:
    any of them
}