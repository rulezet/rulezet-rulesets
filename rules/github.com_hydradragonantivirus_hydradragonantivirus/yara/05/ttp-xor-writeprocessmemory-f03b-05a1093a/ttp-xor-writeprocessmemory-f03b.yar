rule TTP_XOR_WriteProcessMemory_f03b {
  strings:
    $key_f03b = { a7 49 [2] 95 6b [2] 93 5e [2] bd 5e [2] 82 42 }

  condition:
    any of them
}