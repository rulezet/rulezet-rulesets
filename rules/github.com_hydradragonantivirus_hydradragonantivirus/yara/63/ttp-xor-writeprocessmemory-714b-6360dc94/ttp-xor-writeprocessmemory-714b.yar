rule TTP_XOR_WriteProcessMemory_714b {
  strings:
    $key_714b = { 26 39 [2] 14 1b [2] 12 2e [2] 3c 2e [2] 03 32 }

  condition:
    any of them
}