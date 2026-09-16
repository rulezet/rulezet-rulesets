rule TTP_XOR_WriteProcessMemory_f0f6 {
  strings:
    $key_f0f6 = { a7 84 [2] 95 a6 [2] 93 93 [2] bd 93 [2] 82 8f }

  condition:
    any of them
}