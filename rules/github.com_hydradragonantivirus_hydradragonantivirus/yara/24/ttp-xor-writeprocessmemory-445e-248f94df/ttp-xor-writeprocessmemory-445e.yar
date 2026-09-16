rule TTP_XOR_WriteProcessMemory_445e {
  strings:
    $key_445e = { 13 2c [2] 21 0e [2] 27 3b [2] 09 3b [2] 36 27 }

  condition:
    any of them
}