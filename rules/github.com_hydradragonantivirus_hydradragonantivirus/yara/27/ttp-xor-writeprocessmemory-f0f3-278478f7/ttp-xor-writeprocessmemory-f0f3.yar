rule TTP_XOR_WriteProcessMemory_f0f3 {
  strings:
    $key_f0f3 = { a7 81 [2] 95 a3 [2] 93 96 [2] bd 96 [2] 82 8a }

  condition:
    any of them
}