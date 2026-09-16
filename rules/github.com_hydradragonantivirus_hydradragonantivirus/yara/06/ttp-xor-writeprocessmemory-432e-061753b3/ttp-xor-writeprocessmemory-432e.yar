rule TTP_XOR_WriteProcessMemory_432e {
  strings:
    $key_432e = { 14 5c [2] 26 7e [2] 20 4b [2] 0e 4b [2] 31 57 }

  condition:
    any of them
}