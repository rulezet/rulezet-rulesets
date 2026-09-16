rule TTP_XOR_WriteProcessMemory_f065 {
  strings:
    $key_f065 = { a7 17 [2] 95 35 [2] 93 00 [2] bd 00 [2] 82 1c }

  condition:
    any of them
}