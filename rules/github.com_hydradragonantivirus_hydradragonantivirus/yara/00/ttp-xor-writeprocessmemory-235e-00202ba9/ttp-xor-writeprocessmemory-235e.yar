rule TTP_XOR_WriteProcessMemory_235e {
  strings:
    $key_235e = { 74 2c [2] 46 0e [2] 40 3b [2] 6e 3b [2] 51 27 }

  condition:
    any of them
}