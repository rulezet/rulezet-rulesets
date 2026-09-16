rule TTP_XOR_WriteProcessMemory_573b {
  strings:
    $key_573b = { 00 49 [2] 32 6b [2] 34 5e [2] 1a 5e [2] 25 42 }

  condition:
    any of them
}