rule TTP_XOR_WriteProcessMemory_f062 {
  strings:
    $key_f062 = { a7 10 [2] 95 32 [2] 93 07 [2] bd 07 [2] 82 1b }

  condition:
    any of them
}