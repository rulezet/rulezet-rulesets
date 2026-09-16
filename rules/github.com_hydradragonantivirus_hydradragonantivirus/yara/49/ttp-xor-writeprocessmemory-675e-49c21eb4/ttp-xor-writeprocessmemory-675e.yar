rule TTP_XOR_WriteProcessMemory_675e {
  strings:
    $key_675e = { 30 2c [2] 02 0e [2] 04 3b [2] 2a 3b [2] 15 27 }

  condition:
    any of them
}