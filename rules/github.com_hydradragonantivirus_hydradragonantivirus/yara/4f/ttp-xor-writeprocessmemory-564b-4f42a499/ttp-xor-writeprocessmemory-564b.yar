rule TTP_XOR_WriteProcessMemory_564b {
  strings:
    $key_564b = { 01 39 [2] 33 1b [2] 35 2e [2] 1b 2e [2] 24 32 }

  condition:
    any of them
}