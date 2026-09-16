rule TTP_XOR_WriteProcessMemory_f076 {
  strings:
    $key_f076 = { a7 04 [2] 95 26 [2] 93 13 [2] bd 13 [2] 82 0f }

  condition:
    any of them
}