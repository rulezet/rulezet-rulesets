rule TTP_XOR_WriteProcessMemory_434e {
  strings:
    $key_434e = { 14 3c [2] 26 1e [2] 20 2b [2] 0e 2b [2] 31 37 }

  condition:
    any of them
}