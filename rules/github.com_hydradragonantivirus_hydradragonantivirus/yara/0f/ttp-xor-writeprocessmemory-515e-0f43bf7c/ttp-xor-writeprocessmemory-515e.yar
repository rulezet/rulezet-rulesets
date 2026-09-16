rule TTP_XOR_WriteProcessMemory_515e {
  strings:
    $key_515e = { 06 2c [2] 34 0e [2] 32 3b [2] 1c 3b [2] 23 27 }

  condition:
    any of them
}