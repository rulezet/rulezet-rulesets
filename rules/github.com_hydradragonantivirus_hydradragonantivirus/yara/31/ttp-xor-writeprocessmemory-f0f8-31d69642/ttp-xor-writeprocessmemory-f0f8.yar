rule TTP_XOR_WriteProcessMemory_f0f8 {
  strings:
    $key_f0f8 = { a7 8a [2] 95 a8 [2] 93 9d [2] bd 9d [2] 82 81 }

  condition:
    any of them
}