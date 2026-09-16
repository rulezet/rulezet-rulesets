rule TTP_XOR_WriteProcessMemory_f067 {
  strings:
    $key_f067 = { a7 15 [2] 95 37 [2] 93 02 [2] bd 02 [2] 82 1e }

  condition:
    any of them
}