rule TTP_XOR_WriteProcessMemory_f0e1 {
  strings:
    $key_f0e1 = { a7 93 [2] 95 b1 [2] 93 84 [2] bd 84 [2] 82 98 }

  condition:
    any of them
}