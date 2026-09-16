rule TTP_XOR_WriteProcessMemory_0e4e {
  strings:
    $key_0e4e = { 59 3c [2] 6b 1e [2] 6d 2b [2] 43 2b [2] 7c 37 }

  condition:
    any of them
}