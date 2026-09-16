rule TTP_XOR_WriteProcessMemory_f03e {
  strings:
    $key_f03e = { a7 4c [2] 95 6e [2] 93 5b [2] bd 5b [2] 82 47 }

  condition:
    any of them
}