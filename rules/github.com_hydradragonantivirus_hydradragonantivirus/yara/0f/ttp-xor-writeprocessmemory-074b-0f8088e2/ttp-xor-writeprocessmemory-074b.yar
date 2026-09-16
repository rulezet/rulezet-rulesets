rule TTP_XOR_WriteProcessMemory_074b {
  strings:
    $key_074b = { 50 39 [2] 62 1b [2] 64 2e [2] 4a 2e [2] 75 32 }

  condition:
    any of them
}