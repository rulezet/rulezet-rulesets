rule TTP_XOR_WriteProcessMemory_354b {
  strings:
    $key_354b = { 62 39 [2] 50 1b [2] 56 2e [2] 78 2e [2] 47 32 }

  condition:
    any of them
}