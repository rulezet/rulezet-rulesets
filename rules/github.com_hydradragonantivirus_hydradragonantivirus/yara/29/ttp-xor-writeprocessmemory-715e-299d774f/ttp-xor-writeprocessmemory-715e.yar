rule TTP_XOR_WriteProcessMemory_715e {
  strings:
    $key_715e = { 26 2c [2] 14 0e [2] 12 3b [2] 3c 3b [2] 03 27 }

  condition:
    any of them
}