rule TTP_XOR_WriteProcessMemory_f032 {
  strings:
    $key_f032 = { a7 40 [2] 95 62 [2] 93 57 [2] bd 57 [2] 82 4b }

  condition:
    any of them
}