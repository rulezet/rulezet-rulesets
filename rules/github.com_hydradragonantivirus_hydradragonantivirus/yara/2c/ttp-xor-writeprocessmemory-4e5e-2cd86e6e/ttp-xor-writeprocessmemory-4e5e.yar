rule TTP_XOR_WriteProcessMemory_4e5e {
  strings:
    $key_4e5e = { 19 2c [2] 2b 0e [2] 2d 3b [2] 03 3b [2] 3c 27 }

  condition:
    any of them
}