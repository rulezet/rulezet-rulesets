rule TTP_XOR_WriteProcessMemory_644e {
  strings:
    $key_644e = { 33 3c [2] 01 1e [2] 07 2b [2] 29 2b [2] 16 37 }

  condition:
    any of them
}