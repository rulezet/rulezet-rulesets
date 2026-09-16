rule TTP_XOR_WriteProcessMemory_775e {
  strings:
    $key_775e = { 20 2c [2] 12 0e [2] 14 3b [2] 3a 3b [2] 05 27 }

  condition:
    any of them
}