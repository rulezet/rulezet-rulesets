rule TTP_XOR_WriteProcessMemory_1f5e {
  strings:
    $key_1f5e = { 48 2c [2] 7a 0e [2] 7c 3b [2] 52 3b [2] 6d 27 }

  condition:
    any of them
}