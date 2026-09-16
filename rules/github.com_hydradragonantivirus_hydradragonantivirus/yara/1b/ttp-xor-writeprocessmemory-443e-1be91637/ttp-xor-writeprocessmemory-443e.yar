rule TTP_XOR_WriteProcessMemory_443e {
  strings:
    $key_443e = { 13 4c [2] 21 6e [2] 27 5b [2] 09 5b [2] 36 47 }

  condition:
    any of them
}