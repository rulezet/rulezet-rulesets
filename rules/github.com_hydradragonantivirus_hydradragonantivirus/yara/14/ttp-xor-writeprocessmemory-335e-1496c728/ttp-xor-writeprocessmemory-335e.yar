rule TTP_XOR_WriteProcessMemory_335e {
  strings:
    $key_335e = { 64 2c [2] 56 0e [2] 50 3b [2] 7e 3b [2] 41 27 }

  condition:
    any of them
}