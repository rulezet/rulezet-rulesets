rule TTP_XOR_WriteProcessMemory_f041 {
  strings:
    $key_f041 = { a7 33 [2] 95 11 [2] 93 24 [2] bd 24 [2] 82 38 }

  condition:
    any of them
}