rule TTP_XOR_WriteProcessMemory_1d4b {
  strings:
    $key_1d4b = { 4a 39 [2] 78 1b [2] 7e 2e [2] 50 2e [2] 6f 32 }

  condition:
    any of them
}