rule TTP_XOR_WriteProcessMemory_3a4e {
  strings:
    $key_3a4e = { 6d 3c [2] 5f 1e [2] 59 2b [2] 77 2b [2] 48 37 }

  condition:
    any of them
}