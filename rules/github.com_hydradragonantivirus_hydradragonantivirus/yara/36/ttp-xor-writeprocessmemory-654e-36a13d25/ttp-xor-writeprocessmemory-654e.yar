rule TTP_XOR_WriteProcessMemory_654e {
  strings:
    $key_654e = { 32 3c [2] 00 1e [2] 06 2b [2] 28 2b [2] 17 37 }

  condition:
    any of them
}