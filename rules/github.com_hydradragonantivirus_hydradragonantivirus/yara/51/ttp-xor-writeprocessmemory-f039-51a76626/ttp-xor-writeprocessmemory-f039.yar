rule TTP_XOR_WriteProcessMemory_f039 {
  strings:
    $key_f039 = { a7 4b [2] 95 69 [2] 93 5c [2] bd 5c [2] 82 40 }

  condition:
    any of them
}