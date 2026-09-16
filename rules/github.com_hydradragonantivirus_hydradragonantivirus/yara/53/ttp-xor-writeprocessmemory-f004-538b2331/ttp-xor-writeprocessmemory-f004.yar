rule TTP_XOR_WriteProcessMemory_f004 {
  strings:
    $key_f004 = { a7 76 [2] 95 54 [2] 93 61 [2] bd 61 [2] 82 7d }

  condition:
    any of them
}