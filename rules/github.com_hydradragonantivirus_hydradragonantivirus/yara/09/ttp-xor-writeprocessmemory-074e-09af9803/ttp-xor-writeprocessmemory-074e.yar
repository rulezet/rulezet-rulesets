rule TTP_XOR_WriteProcessMemory_074e {
  strings:
    $key_074e = { 50 3c [2] 62 1e [2] 64 2b [2] 4a 2b [2] 75 37 }

  condition:
    any of them
}