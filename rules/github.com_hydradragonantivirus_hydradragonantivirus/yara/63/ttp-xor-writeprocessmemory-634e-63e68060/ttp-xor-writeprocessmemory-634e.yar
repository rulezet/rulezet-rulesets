rule TTP_XOR_WriteProcessMemory_634e {
  strings:
    $key_634e = { 34 3c [2] 06 1e [2] 00 2b [2] 2e 2b [2] 11 37 }

  condition:
    any of them
}