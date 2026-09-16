rule TTP_XOR_WriteProcessMemory_f002 {
  strings:
    $key_f002 = { a7 70 [2] 95 52 [2] 93 67 [2] bd 67 [2] 82 7b }

  condition:
    any of them
}