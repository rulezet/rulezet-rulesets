rule TTP_XOR_WriteProcessMemory_f02b {
  strings:
    $key_f02b = { a7 59 [2] 95 7b [2] 93 4e [2] bd 4e [2] 82 52 }

  condition:
    any of them
}