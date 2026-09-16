rule TTP_XOR_WriteProcessMemory_f059 {
  strings:
    $key_f059 = { a7 2b [2] 95 09 [2] 93 3c [2] bd 3c [2] 82 20 }

  condition:
    any of them
}