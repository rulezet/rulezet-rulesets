rule TTP_XOR_WriteProcessMemory_2f5e {
  strings:
    $key_2f5e = { 78 2c [2] 4a 0e [2] 4c 3b [2] 62 3b [2] 5d 27 }

  condition:
    any of them
}