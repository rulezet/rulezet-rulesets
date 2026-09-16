rule TTP_XOR_WriteProcessMemory_505e {
  strings:
    $key_505e = { 07 2c [2] 35 0e [2] 33 3b [2] 1d 3b [2] 22 27 }

  condition:
    any of them
}