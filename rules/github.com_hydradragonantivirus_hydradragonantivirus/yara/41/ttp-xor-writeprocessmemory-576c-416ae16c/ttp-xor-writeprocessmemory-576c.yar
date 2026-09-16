rule TTP_XOR_WriteProcessMemory_576c {
  strings:
    $key_576c = { 00 1e [2] 32 3c [2] 34 09 [2] 1a 09 [2] 25 15 }

  condition:
    any of them
}