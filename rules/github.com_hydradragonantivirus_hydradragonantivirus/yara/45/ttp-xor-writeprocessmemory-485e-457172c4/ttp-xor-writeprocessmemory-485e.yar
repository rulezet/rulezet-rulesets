rule TTP_XOR_WriteProcessMemory_485e {
  strings:
    $key_485e = { 1f 2c [2] 2d 0e [2] 2b 3b [2] 05 3b [2] 3a 27 }

  condition:
    any of them
}