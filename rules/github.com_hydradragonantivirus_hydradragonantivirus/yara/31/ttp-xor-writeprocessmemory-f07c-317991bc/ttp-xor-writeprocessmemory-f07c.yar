rule TTP_XOR_WriteProcessMemory_f07c {
  strings:
    $key_f07c = { a7 0e [2] 95 2c [2] 93 19 [2] bd 19 [2] 82 05 }

  condition:
    any of them
}