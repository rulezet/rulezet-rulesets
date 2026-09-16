rule TTP_XOR_WriteProcessMemory_506b {
  strings:
    $key_506b = { 07 19 [2] 35 3b [2] 33 0e [2] 1d 0e [2] 22 12 }

  condition:
    any of them
}