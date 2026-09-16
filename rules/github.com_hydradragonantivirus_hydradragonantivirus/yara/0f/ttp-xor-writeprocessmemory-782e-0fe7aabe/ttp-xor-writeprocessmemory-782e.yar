rule TTP_XOR_WriteProcessMemory_782e {
  strings:
    $key_782e = { 2f 5c [2] 1d 7e [2] 1b 4b [2] 35 4b [2] 0a 57 }

  condition:
    any of them
}