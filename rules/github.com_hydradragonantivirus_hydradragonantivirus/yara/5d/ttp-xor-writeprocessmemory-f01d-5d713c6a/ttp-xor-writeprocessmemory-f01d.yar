rule TTP_XOR_WriteProcessMemory_f01d {
  strings:
    $key_f01d = { a7 6f [2] 95 4d [2] 93 78 [2] bd 78 [2] 82 64 }

  condition:
    any of them
}