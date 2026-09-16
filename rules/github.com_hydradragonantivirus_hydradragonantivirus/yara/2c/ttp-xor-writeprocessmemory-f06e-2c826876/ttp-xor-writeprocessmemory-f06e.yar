rule TTP_XOR_WriteProcessMemory_f06e {
  strings:
    $key_f06e = { a7 1c [2] 95 3e [2] 93 0b [2] bd 0b [2] 82 17 }

  condition:
    any of them
}