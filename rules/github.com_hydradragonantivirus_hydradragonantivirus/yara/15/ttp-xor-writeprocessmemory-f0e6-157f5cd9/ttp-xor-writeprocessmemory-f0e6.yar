rule TTP_XOR_WriteProcessMemory_f0e6 {
  strings:
    $key_f0e6 = { a7 94 [2] 95 b6 [2] 93 83 [2] bd 83 [2] 82 9f }

  condition:
    any of them
}