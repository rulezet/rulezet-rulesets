rule TTP_XOR_WriteProcessMemory_f02c {
  strings:
    $key_f02c = { a7 5e [2] 95 7c [2] 93 49 [2] bd 49 [2] 82 55 }

  condition:
    any of them
}