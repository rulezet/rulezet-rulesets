rule TTP_XOR_WriteProcessMemory_573e {
  strings:
    $key_573e = { 00 4c [2] 32 6e [2] 34 5b [2] 1a 5b [2] 25 47 }

  condition:
    any of them
}