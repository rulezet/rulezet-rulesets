rule TTP_XOR_WriteProcessMemory_f009 {
  strings:
    $key_f009 = { a7 7b [2] 95 59 [2] 93 6c [2] bd 6c [2] 82 70 }

  condition:
    any of them
}