rule TTP_XOR_WriteProcessMemory_f77e {
  strings:
    $key_f77e = { a0 0c [2] 92 2e [2] 94 1b [2] ba 1b [2] 85 07 }

  condition:
    any of them
}