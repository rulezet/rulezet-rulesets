rule TTP_XOR_WriteProcessMemory_f0f1 {
  strings:
    $key_f0f1 = { a7 83 [2] 95 a1 [2] 93 94 [2] bd 94 [2] 82 88 }

  condition:
    any of them
}