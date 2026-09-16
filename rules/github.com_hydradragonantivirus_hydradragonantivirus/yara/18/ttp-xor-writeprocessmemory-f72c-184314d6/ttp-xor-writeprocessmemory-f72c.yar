rule TTP_XOR_WriteProcessMemory_f72c {
  strings:
    $key_f72c = { a0 5e [2] 92 7c [2] 94 49 [2] ba 49 [2] 85 55 }

  condition:
    any of them
}