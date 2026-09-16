rule TTP_XOR_WriteProcessMemory_f043 {
  strings:
    $key_f043 = { a7 31 [2] 95 13 [2] 93 26 [2] bd 26 [2] 82 3a }

  condition:
    any of them
}