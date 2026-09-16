rule TTP_XOR_WriteProcessMemory_f052 {
  strings:
    $key_f052 = { a7 20 [2] 95 02 [2] 93 37 [2] bd 37 [2] 82 2b }

  condition:
    any of them
}