rule TTP_XOR_WriteProcessMemory_f013 {
  strings:
    $key_f013 = { a7 61 [2] 95 43 [2] 93 76 [2] bd 76 [2] 82 6a }

  condition:
    any of them
}