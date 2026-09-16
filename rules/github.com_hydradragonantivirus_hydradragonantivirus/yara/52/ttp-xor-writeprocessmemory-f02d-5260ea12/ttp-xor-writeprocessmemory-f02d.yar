rule TTP_XOR_WriteProcessMemory_f02d {
  strings:
    $key_f02d = { a7 5f [2] 95 7d [2] 93 48 [2] bd 48 [2] 82 54 }

  condition:
    any of them
}