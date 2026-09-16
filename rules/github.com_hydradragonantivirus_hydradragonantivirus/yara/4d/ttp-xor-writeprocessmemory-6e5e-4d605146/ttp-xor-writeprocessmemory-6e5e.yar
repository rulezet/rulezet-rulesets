rule TTP_XOR_WriteProcessMemory_6e5e {
  strings:
    $key_6e5e = { 39 2c [2] 0b 0e [2] 0d 3b [2] 23 3b [2] 1c 27 }

  condition:
    any of them
}