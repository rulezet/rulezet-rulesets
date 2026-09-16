rule TTP_XOR_WriteProcessMemory_f005 {
  strings:
    $key_f005 = { a7 77 [2] 95 55 [2] 93 60 [2] bd 60 [2] 82 7c }

  condition:
    any of them
}