rule TTP_XOR_WriteProcessMemory_f025 {
  strings:
    $key_f025 = { a7 57 [2] 95 75 [2] 93 40 [2] bd 40 [2] 82 5c }

  condition:
    any of them
}