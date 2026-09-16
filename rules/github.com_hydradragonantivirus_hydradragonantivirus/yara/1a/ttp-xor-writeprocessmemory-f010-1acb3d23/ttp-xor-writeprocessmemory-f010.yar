rule TTP_XOR_WriteProcessMemory_f010 {
  strings:
    $key_f010 = { a7 62 [2] 95 40 [2] 93 75 [2] bd 75 [2] 82 69 }

  condition:
    any of them
}