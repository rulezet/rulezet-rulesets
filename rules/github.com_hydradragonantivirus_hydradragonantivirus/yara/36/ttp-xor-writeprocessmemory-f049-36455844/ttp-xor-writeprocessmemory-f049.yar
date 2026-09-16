rule TTP_XOR_WriteProcessMemory_f049 {
  strings:
    $key_f049 = { a7 3b [2] 95 19 [2] 93 2c [2] bd 2c [2] 82 30 }

  condition:
    any of them
}