rule TTP_XOR_WriteProcessMemory_f051 {
  strings:
    $key_f051 = { a7 23 [2] 95 01 [2] 93 34 [2] bd 34 [2] 82 28 }

  condition:
    any of them
}