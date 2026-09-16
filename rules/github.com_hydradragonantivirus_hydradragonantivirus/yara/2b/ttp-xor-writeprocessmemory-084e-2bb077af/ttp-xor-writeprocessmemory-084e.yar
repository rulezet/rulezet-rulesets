rule TTP_XOR_WriteProcessMemory_084e {
  strings:
    $key_084e = { 5f 3c [2] 6d 1e [2] 6b 2b [2] 45 2b [2] 7a 37 }

  condition:
    any of them
}