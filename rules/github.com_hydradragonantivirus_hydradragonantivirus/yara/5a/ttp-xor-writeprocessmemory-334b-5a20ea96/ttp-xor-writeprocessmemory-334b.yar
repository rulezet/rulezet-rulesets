rule TTP_XOR_WriteProcessMemory_334b {
  strings:
    $key_334b = { 64 39 [2] 56 1b [2] 50 2e [2] 7e 2e [2] 41 32 }

  condition:
    any of them
}