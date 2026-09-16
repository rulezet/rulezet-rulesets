rule TTP_XOR_WriteProcessMemory_555e {
  strings:
    $key_555e = { 02 2c [2] 30 0e [2] 36 3b [2] 18 3b [2] 27 27 }

  condition:
    any of them
}