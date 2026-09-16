rule TTP_XOR_WriteProcessMemory_f008 {
  strings:
    $key_f008 = { a7 7a [2] 95 58 [2] 93 6d [2] bd 6d [2] 82 71 }

  condition:
    any of them
}