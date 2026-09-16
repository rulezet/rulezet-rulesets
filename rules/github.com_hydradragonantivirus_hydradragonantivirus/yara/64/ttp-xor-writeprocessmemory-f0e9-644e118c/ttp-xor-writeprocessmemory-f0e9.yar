rule TTP_XOR_WriteProcessMemory_f0e9 {
  strings:
    $key_f0e9 = { a7 9b [2] 95 b9 [2] 93 8c [2] bd 8c [2] 82 90 }

  condition:
    any of them
}