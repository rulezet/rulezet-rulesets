rule TTP_XOR_WriteProcessMemory_5c5e {
  strings:
    $key_5c5e = { 0b 2c [2] 39 0e [2] 3f 3b [2] 11 3b [2] 2e 27 }

  condition:
    any of them
}