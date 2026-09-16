rule TTP_XOR_WriteProcessMemory_0e4b {
  strings:
    $key_0e4b = { 59 39 [2] 6b 1b [2] 6d 2e [2] 43 2e [2] 7c 32 }

  condition:
    any of them
}