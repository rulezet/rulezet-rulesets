rule TTP_XOR_WriteProcessMemory_474e {
  strings:
    $key_474e = { 10 3c [2] 22 1e [2] 24 2b [2] 0a 2b [2] 35 37 }

  condition:
    any of them
}