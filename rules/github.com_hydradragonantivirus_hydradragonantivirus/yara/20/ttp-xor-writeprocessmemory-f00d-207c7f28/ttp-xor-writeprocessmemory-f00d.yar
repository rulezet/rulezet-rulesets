rule TTP_XOR_WriteProcessMemory_f00d {
  strings:
    $key_f00d = { a7 7f [2] 95 5d [2] 93 68 [2] bd 68 [2] 82 74 }

  condition:
    any of them
}