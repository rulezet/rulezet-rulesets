rule TTP_XOR_WriteProcessMemory_f078 {
  strings:
    $key_f078 = { a7 0a [2] 95 28 [2] 93 1d [2] bd 1d [2] 82 01 }

  condition:
    any of them
}