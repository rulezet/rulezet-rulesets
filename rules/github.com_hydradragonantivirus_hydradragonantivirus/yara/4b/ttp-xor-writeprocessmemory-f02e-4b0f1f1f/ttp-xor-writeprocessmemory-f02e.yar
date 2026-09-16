rule TTP_XOR_WriteProcessMemory_f02e {
  strings:
    $key_f02e = { a7 5c [2] 95 7e [2] 93 4b [2] bd 4b [2] 82 57 }

  condition:
    any of them
}