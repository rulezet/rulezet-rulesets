rule TTP_XOR_WriteProcessMemory_f0f7 {
  strings:
    $key_f0f7 = { a7 85 [2] 95 a7 [2] 93 92 [2] bd 92 [2] 82 8e }

  condition:
    any of them
}