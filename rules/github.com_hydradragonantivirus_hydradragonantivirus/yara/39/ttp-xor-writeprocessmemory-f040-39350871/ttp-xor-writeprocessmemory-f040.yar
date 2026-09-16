rule TTP_XOR_WriteProcessMemory_f040 {
  strings:
    $key_f040 = { a7 32 [2] 95 10 [2] 93 25 [2] bd 25 [2] 82 39 }

  condition:
    any of them
}