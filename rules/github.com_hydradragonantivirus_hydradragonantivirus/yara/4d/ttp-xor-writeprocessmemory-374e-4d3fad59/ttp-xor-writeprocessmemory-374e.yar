rule TTP_XOR_WriteProcessMemory_374e {
  strings:
    $key_374e = { 60 3c [2] 52 1e [2] 54 2b [2] 7a 2b [2] 45 37 }

  condition:
    any of them
}