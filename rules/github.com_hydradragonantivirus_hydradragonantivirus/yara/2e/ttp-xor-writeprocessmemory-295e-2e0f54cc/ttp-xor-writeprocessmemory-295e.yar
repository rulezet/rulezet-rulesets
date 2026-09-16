rule TTP_XOR_WriteProcessMemory_295e {
  strings:
    $key_295e = { 7e 2c [2] 4c 0e [2] 4a 3b [2] 64 3b [2] 5b 27 }

  condition:
    any of them
}