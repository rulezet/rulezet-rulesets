rule TTP_XOR_WriteProcessMemory_125e {
  strings:
    $key_125e = { 45 2c [2] 77 0e [2] 71 3b [2] 5f 3b [2] 60 27 }

  condition:
    any of them
}