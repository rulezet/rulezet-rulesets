rule TTP_XOR_WriteProcessMemory_f00c {
  strings:
    $key_f00c = { a7 7e [2] 95 5c [2] 93 69 [2] bd 69 [2] 82 75 }

  condition:
    any of them
}