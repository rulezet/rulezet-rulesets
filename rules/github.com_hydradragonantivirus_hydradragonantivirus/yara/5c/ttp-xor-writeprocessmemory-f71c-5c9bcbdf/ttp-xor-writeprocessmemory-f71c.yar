rule TTP_XOR_WriteProcessMemory_f71c {
  strings:
    $key_f71c = { a0 6e [2] 92 4c [2] 94 79 [2] ba 79 [2] 85 65 }

  condition:
    any of them
}