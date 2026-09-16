rule TTP_XOR_WriteProcessMemory_f0e8 {
  strings:
    $key_f0e8 = { a7 9a [2] 95 b8 [2] 93 8d [2] bd 8d [2] 82 91 }

  condition:
    any of them
}