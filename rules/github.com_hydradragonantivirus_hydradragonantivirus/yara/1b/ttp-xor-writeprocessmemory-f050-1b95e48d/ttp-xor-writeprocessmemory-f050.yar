rule TTP_XOR_WriteProcessMemory_f050 {
  strings:
    $key_f050 = { a7 22 [2] 95 00 [2] 93 35 [2] bd 35 [2] 82 29 }

  condition:
    any of them
}