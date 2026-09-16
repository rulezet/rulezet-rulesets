rule TTP_XOR_WriteProcessMemory_f019 {
  strings:
    $key_f019 = { a7 6b [2] 95 49 [2] 93 7c [2] bd 7c [2] 82 60 }

  condition:
    any of them
}