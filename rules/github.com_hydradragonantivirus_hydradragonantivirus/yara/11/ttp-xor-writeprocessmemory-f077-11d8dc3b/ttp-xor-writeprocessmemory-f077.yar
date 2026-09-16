rule TTP_XOR_WriteProcessMemory_f077 {
  strings:
    $key_f077 = { a7 05 [2] 95 27 [2] 93 12 [2] bd 12 [2] 82 0e }

  condition:
    any of them
}