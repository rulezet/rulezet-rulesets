rule TTP_XOR_WriteProcessMemory_f055 {
  strings:
    $key_f055 = { a7 27 [2] 95 05 [2] 93 30 [2] bd 30 [2] 82 2c }

  condition:
    any of them
}