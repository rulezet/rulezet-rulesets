rule TTP_XOR_WriteProcessMemory_575b {
  strings:
    $key_575b = { 00 29 [2] 32 0b [2] 34 3e [2] 1a 3e [2] 25 22 }

  condition:
    any of them
}