rule TTP_XOR_WriteProcessMemory_575e {
  strings:
    $key_575e = { 00 2c [2] 32 0e [2] 34 3b [2] 1a 3b [2] 25 27 }

  condition:
    any of them
}