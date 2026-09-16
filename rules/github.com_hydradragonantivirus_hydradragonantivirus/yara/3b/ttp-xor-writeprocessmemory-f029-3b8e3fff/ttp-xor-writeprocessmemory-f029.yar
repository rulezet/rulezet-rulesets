rule TTP_XOR_WriteProcessMemory_f029 {
  strings:
    $key_f029 = { a7 5b [2] 95 79 [2] 93 4c [2] bd 4c [2] 82 50 }

  condition:
    any of them
}