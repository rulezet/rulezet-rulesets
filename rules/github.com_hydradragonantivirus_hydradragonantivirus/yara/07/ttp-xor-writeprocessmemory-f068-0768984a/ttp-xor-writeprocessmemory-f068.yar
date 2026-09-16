rule TTP_XOR_WriteProcessMemory_f068 {
  strings:
    $key_f068 = { a7 1a [2] 95 38 [2] 93 0d [2] bd 0d [2] 82 11 }

  condition:
    any of them
}