rule TTP_XOR_WriteProcessMemory_7e5e {
  strings:
    $key_7e5e = { 29 2c [2] 1b 0e [2] 1d 3b [2] 33 3b [2] 0c 27 }

  condition:
    any of them
}