rule TTP_XOR_WriteProcessMemory_f000 {
  strings:
    $key_f000 = { a7 72 [2] 95 50 [2] 93 65 [2] bd 65 [2] 82 79 }

  condition:
    any of them
}