rule TTP_XOR_WriteProcessMemory_3a5e {
  strings:
    $key_3a5e = { 6d 2c [2] 5f 0e [2] 59 3b [2] 77 3b [2] 48 27 }

  condition:
    any of them
}