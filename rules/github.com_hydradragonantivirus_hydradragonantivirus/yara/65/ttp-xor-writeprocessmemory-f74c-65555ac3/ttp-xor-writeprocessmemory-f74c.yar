rule TTP_XOR_WriteProcessMemory_f74c {
  strings:
    $key_f74c = { a0 3e [2] 92 1c [2] 94 29 [2] ba 29 [2] 85 35 }

  condition:
    any of them
}