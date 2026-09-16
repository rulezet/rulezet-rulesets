rule TTP_XOR_WriteProcessMemory_f0e7 {
  strings:
    $key_f0e7 = { a7 95 [2] 95 b7 [2] 93 82 [2] bd 82 [2] 82 9e }

  condition:
    any of them
}