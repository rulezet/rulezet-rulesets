rule TTP_XOR_WriteProcessMemory_644b {
  strings:
    $key_644b = { 33 39 [2] 01 1b [2] 07 2e [2] 29 2e [2] 16 32 }

  condition:
    any of them
}