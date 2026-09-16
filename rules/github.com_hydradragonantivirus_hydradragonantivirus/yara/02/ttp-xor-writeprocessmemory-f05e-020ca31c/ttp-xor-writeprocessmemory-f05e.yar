rule TTP_XOR_WriteProcessMemory_f05e {
  strings:
    $key_f05e = { a7 2c [2] 95 0e [2] 93 3b [2] bd 3b [2] 82 27 }

  condition:
    any of them
}